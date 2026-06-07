"""F1 — the spine. Supervisor + 4 specialist subagents on splunklib.ai.

  Supervisor (pro)        — orchestrates; fans out, assembles the IncidentBrief.
  Correlator (flash)      — multi-index timeline + blast-radius via SPL tools.
  Adjudicator (pro)       — verdict + confidence + MITRE mapping.
  Responder (flash)       — SOP-grounded, human-approved containment actions.
  Detection Engineer (flash) — THE WOW: proposes the SPL detection fix.

Subagents are Agent instances passed via agents=[...] with name+description
(captured in Day-0 spike). Each is an async context manager and must be entered
(AsyncExitStack) before the supervisor invokes. The supervisor's output_schema is
IncidentBrief so the whole run resolves to one typed object (F2).
"""
from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Any

from splunklib.ai import Agent
from splunklib.ai.messages import HumanMessage

from .config import flash_model, pro_model
from .mcp_wiring import (
    RemoteToolsEvidenceFilter,
    make_agent_logger,
    resolve_correlator_tool_settings,
)
from splunklib.ai.tool_settings import ToolSettings
from .schemas import IncidentBrief


def _text_of(message: Any) -> str:
    """final_message.content may be str or list[TextBlock] (spike learning)."""
    content = message.content
    if isinstance(content, str):
        return content
    parts = []
    for block in content:
        text = getattr(block, "text", None)
        parts.append(text if text is not None else str(block))
    return "".join(parts)


# ---- subagent prompts (Splunk SOC voice; load-bearing, not decorative) ----

CORRELATOR_PROMPT = (
    "You are the Correlator, a Splunk SOC analyst subagent. Given a fired "
    "detection, reconstruct a multi-index event timeline and identify the "
    "blast-radius entities (hosts and accounts) implicated, ranked by exposure. "
    "Use the auth and edr indexes.\n"
    "\n"
    "When Splunk MCP Server tools are available to you (splunk_run_query, "
    "splunk_get_indexes, splunk_get_metadata), you MUST use them to VERIFY your "
    "findings against the live indexes before answering — do not answer from the "
    "passed-in text alone. Make at least one splunk_run_query call. Concretely: "
    "call splunk_run_query with `search index=auth action=logon logon_type=3 | "
    "stats dc(dest) AS distinct_dests values(dest) AS dests by user` to confirm "
    "the admin-share fan-out, and splunk_run_query with `search index=edr signal "
    "IN (suspicious_download,remote_exec_tool) | table _time host user signal` to "
    "confirm the EDR attack-tool signals. Optionally call splunk_get_indexes to "
    "ground which indexes exist. If no MCP tools are available, reason directly "
    "over the evidence you were given. Either way, be precise and cite the index "
    "each event came from. Return your findings as text: the timeline plus the "
    "ranked blast-radius entities (the origin host and every pivoted-to host/"
    "account), and note that your numbers were confirmed via the Splunk MCP Server."
)

ADJUDICATOR_PROMPT = (
    "You are the Adjudicator, a senior Splunk security analyst subagent. Given "
    "the correlated timeline and entities, decide whether the detection is a "
    "true_positive, false_positive, or inconclusive, with a 0-1 confidence and "
    "severity. Map the activity to MITRE ATT&CK technique IDs (e.g. T1021.002 "
    "SMB/Admin Shares, T1078 Valid Accounts). Justify the verdict from evidence."
)

RESPONDER_PROMPT = (
    "You are the Responder, a Splunk SOAR-style subagent. Propose SOP-grounded "
    "containment actions (e.g. isolate host, disable account, kill session) for "
    "a confirmed incident. EVERY action is dry_run=true and requires_approval="
    "true — you NEVER auto-execute. Ground each action's rationale in the "
    "evidence. Prefer the least-privilege action that contains the blast radius."
)

DETECTION_ENGINEER_PROMPT = (
    "You are the Detection Engineer, a Splunk content developer subagent. You "
    "close the self-improving loop: you rewrite the SPL correlation search so it "
    "stops over-firing WITHOUT losing the real attack.\n"
    "\n"
    "Diagnose precisely why the current detection mis-fired. In this incident the "
    "current rule counts distinct admin-share destinations per account and alerts "
    "above a flat threshold, so it CANNOT tell a legitimate backup service account "
    "(svc_backup touching many file servers nightly) apart from a compromised one. "
    "The discriminating signal is the EDR context: the true positive is preceded "
    "by a suspicious_download and a remote_exec_tool (PsExec) signal on the origin "
    "host within a short window; the benign baseline has no such EDR signal.\n"
    "\n"
    "Your fix MUST: (1) keep the existing admin-share fan-out logic that catches "
    "the lateral movement (do NOT delete the true positive); (2) ADD a correlation "
    "to the edr index so the rule only fires when the same host+account also shows "
    "an attack-tool EDR signal in the window (e.g. join/subsearch on host against "
    "`index=edr signal IN (suspicious_download,remote_exec_tool)`), which removes "
    "the service-account false-positive class; (3) be runnable, syntactically valid "
    "SPL using real Splunk commands (stats, where, join, subsearch, eval), no "
    "pseudo-code.\n"
    "\n"
    "Return ALL of these fields:\n"
    "  problem        — one sentence on WHY the current rule over-fires.\n"
    "  current_spl    — the existing detection SPL, verbatim.\n"
    "  proposed_spl   — the full improved SPL (multi-line, runnable).\n"
    "  spl_diff       — a UNIFIED DIFF: a line '--- current detection', a line "
    "'+++ proposed detection', then '-' lines for removed SPL and '+' lines for "
    "added SPL. Show the EDR-correlation addition as '+' lines. This diff is the "
    "centerpiece of the brief — make it crisp and readable.\n"
    "  expected_effect— concrete and quantified, e.g. 'eliminates the recurring "
    "svc_backup / svc_monitor false positives (the entire service-account FP "
    "class) while still firing on the WKS-014 compromise because it alone carries "
    "the EDR attack-tool signal'.\n"
    "\n"
    "Never weaken the rule into something that would miss the WKS-014 true positive."
)

SUPERVISOR_PROMPT = (
    "You are the Sentinel Brief supervisor, orchestrating a SOC war room. When a "
    "detection fires you MUST delegate: use the 'correlator' subagent to build "
    "the timeline and blast radius; the 'adjudicator' subagent for the verdict, "
    "confidence, severity and MITRE mapping; the 'responder' subagent for "
    "human-approved containment actions; and the 'detection_engineer' subagent "
    "for the improved SPL detection. Then assemble ONE structured IncidentBrief "
    "from their findings. Every proposed action must remain dry-run and require "
    "human approval. Be auditable, not chatty."
)


def build_subagents(
    service: Any,
    *,
    evidence: RemoteToolsEvidenceFilter | None = None,
    corr_tool_settings: ToolSettings | None = None,
    corr_logger: Any | None = None,
) -> dict[str, Agent]:
    """Construct the 4 specialist subagents (not yet entered).

    B6: the Correlator is wired with the remote Splunk MCP Server tools when
    `corr_tool_settings.remote` is set (resolved by the async probe in
    run_sentinel_brief, gated on the live backend). In mock mode, or if the MCP
    probe fails, tool_settings.remote is None and the Correlator runs on its
    local-SPL reasoning path (R-fallback) — topology and every other subagent are
    identical. The Correlator gets a DEBUG logger whose filter captures the SDK's
    `Loaded remote_tools=[...]` evidence line.
    """
    if corr_logger is None:
        corr_logger, _ = make_agent_logger()
    if evidence is not None:
        # share the caller's evidence collector so run_sentinel_brief can read it
        corr_logger.addFilter(evidence)

    correlator_kwargs: dict[str, Any] = {}
    if corr_tool_settings is not None and corr_tool_settings.remote is not None:
        correlator_kwargs["tool_settings"] = corr_tool_settings
        correlator_kwargs["logger"] = corr_logger

    return {
        "correlator": Agent(
            model=flash_model(),
            system_prompt=CORRELATOR_PROMPT,
            service=service,
            name="correlator",
            description=(
                "Reconstructs the multi-index event timeline and ranks "
                "blast-radius entities for a fired detection using SPL, querying "
                "Splunk through the Splunk MCP Server (splunk_run_query) when "
                "available."
            ),
            **correlator_kwargs,
        ),
        "adjudicator": Agent(
            model=pro_model(),
            system_prompt=ADJUDICATOR_PROMPT,
            service=service,
            name="adjudicator",
            description=(
                "Decides verdict (true/false positive), confidence, severity, "
                "and maps activity to MITRE ATT&CK technique IDs."
            ),
        ),
        "responder": Agent(
            model=flash_model(),
            system_prompt=RESPONDER_PROMPT,
            service=service,
            name="responder",
            description=(
                "Proposes SOP-grounded, dry-run, human-approved containment "
                "actions for a confirmed incident."
            ),
        ),
        "detection_engineer": Agent(
            model=flash_model(),
            system_prompt=DETECTION_ENGINEER_PROMPT,
            service=service,
            name="detection_engineer",
            description=(
                "Proposes an improved SPL detection that removes the "
                "false-positive class while keeping the true positive (the "
                "self-improving detection loop)."
            ),
        ),
    }


def build_supervisor(service: Any, subagents: dict[str, Agent]) -> Agent:
    """The orchestrator. output_schema=IncidentBrief makes the run resolve to
    one typed object (F2)."""
    return Agent(
        model=pro_model(),
        system_prompt=SUPERVISOR_PROMPT,
        service=service,
        agents=list(subagents.values()),
        output_schema=IncidentBrief,
    )


async def run_sentinel_brief(
    service: Any,
    detection_context: str,
    *,
    mcp_evidence: RemoteToolsEvidenceFilter | None = None,
) -> IncidentBrief:
    """End-to-end: fire a detection -> supervisor fans out -> typed IncidentBrief.

    This is the vertical slice (D3 gate). Works on MockService today; swaps to a
    real splunklib.client.connect Service at Lane-A merge with no code change here.

    B6: pass an optional `mcp_evidence` collector to receive the SDK's
    `Loaded remote_tools=[...]` line + MCP tool-call traces captured during the
    Correlator's run (for MCP-EVIDENCE.md). Omitting it leaves behavior identical.
    """
    # B6: resolve the Correlator's MCP tool settings INSIDE the running loop so the
    # remote-MCP probe (which is async) can run. Live + probe-OK -> remote tools;
    # mock or probe-fail -> remote=None (graceful local-SPL fallback). This never
    # raises out: the probe swallows failures and returns the no-remote settings.
    corr_logger, _ = make_agent_logger()
    if mcp_evidence is not None:
        corr_logger.addFilter(mcp_evidence)
    corr_tool_settings = await resolve_correlator_tool_settings(service, logger=corr_logger)

    subagents = build_subagents(
        service,
        evidence=mcp_evidence,
        corr_tool_settings=corr_tool_settings,
        corr_logger=corr_logger,
    )
    supervisor = build_supervisor(service, subagents)

    async with AsyncExitStack() as stack:
        for sub in subagents.values():
            await stack.enter_async_context(sub)
        sup = await stack.enter_async_context(supervisor)

        response = await sup.invoke_with_data(
            instructions=(
                "A detection has fired. Investigate it end to end and return a "
                "complete IncidentBrief: verdict, severity, confidence, MITRE "
                "techniques, multi-index timeline, ranked blast-radius entities, "
                "and human-approved containment actions. Then ALWAYS populate "
                "proposed_detection via the detection_engineer: it must keep the "
                "admin-share fan-out that catches the true positive, ADD an "
                "edr-index correlation on the EDR attack-tool signal so the rule "
                "stops firing on legitimate backup service accounts, and present "
                "the change as a unified diff (--- current / +++ proposed, with "
                "-/+ lines). This detection fix is the centerpiece of the brief."
            ),
            data=detection_context,
        )
        brief = response.structured_output
        assert isinstance(brief, IncidentBrief), f"expected IncidentBrief, got {type(brief)}"
        return brief
