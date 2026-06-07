"""Scripted detection -> incident brief E2E (the <3-min demo path, D3 slice).

Runs the full supervisor + 4-subagent spine on the seeded lateral-movement
scenario via MockService (no live Splunk needed). At Lane-A merge, swap
MockService for splunklib.client.connect(...) — nothing else changes.

Run (project is taken from ADC if GOOGLE_CLOUD_PROJECT is unset):
  GOOGLE_CLOUD_PROJECT=your-gcp-project GOOGLE_CLOUD_LOCATION=us-central1 \
  sentinel_brief/.venv/Scripts/python demo.py
"""
from __future__ import annotations

import asyncio
import os

from sentinel_brief.agents import run_sentinel_brief
from sentinel_brief.live_context import build_live_detection_context
from sentinel_brief.mcp_wiring import RemoteToolsEvidenceFilter
from sentinel_brief.mock_service import (
    SEED_AUTH_EVENTS,
    SEED_CURRENT_DETECTION_SPL,
    SEED_EDR_EVENTS,
    MockService,
)
from sentinel_brief.render import render_brief
from sentinel_brief.service_factory import make_service

DETECTION_NAME = "Excessive Admin-Share Logons by Single Account"


def _fired_detection_context() -> str:
    """Compose the seeded detection + evidence the supervisor investigates."""
    auth = "\n".join(
        f"  {e['_time']} {e['host']} user={e['user']} -> {e['dest']} ({e['share']})"
        for e in SEED_AUTH_EVENTS
    )
    edr = "\n".join(
        f"  {e['_time']} {e['host']} user={e['user']} {e['process']} :: {e['signal']}"
        for e in SEED_EDR_EVENTS
    )
    return (
        f"FIRED DETECTION: {DETECTION_NAME}\n"
        f"Current detection SPL (known to over-fire on service accounts):\n"
        f"{SEED_CURRENT_DETECTION_SPL}\n\n"
        f"auth index events:\n{auth}\n\n"
        f"edr index events:\n{edr}\n\n"
        "Note: svc_backup is a legitimate backup service account that normally "
        "touches a few file servers nightly — the current rule over-fires on it, "
        "but THIS run also shows a preceding suspicious PowerShell download on "
        "WKS-014 and PsExec remote-exec, which distinguishes a real compromise."
    )


async def main() -> int:
    # B5: backend selector. SENTINEL_BACKEND=live (default) -> real Splunk via
    # .env; =mock -> offline MockService. The agent spine is identical either way.
    service = make_service()
    is_live = not isinstance(service, MockService)
    backend = "live Splunk" if is_live else "mock"

    # Evidence source swaps with the backend; everything downstream is unchanged.
    if is_live:
        context = build_live_detection_context(service, DETECTION_NAME)
    else:
        context = _fired_detection_context()

    print(f"[demo] backend: {backend}")
    print(f"[demo] detection fired: {DETECTION_NAME}")
    print("[demo] supervisor fanning out to correlator/adjudicator/responder/"
          "detection_engineer ...\n")

    # B6: collect MCP-tool evidence (the SDK's `Loaded remote_tools=[...]` line +
    # any MCP tool-call trace) emitted by the Correlator during the run.
    mcp_evidence = RemoteToolsEvidenceFilter()
    brief = await run_sentinel_brief(service, context, mcp_evidence=mcp_evidence)
    # Stamp the detection name if the model didn't echo it verbatim.
    if not brief.detection_name:
        brief.detection_name = DETECTION_NAME

    print(render_brief(brief))

    if mcp_evidence.captured:
        print("\n[demo] Splunk MCP Server evidence (Correlator wired via MCP):")
        for line in mcp_evidence.captured:
            print(f"[mcp] {line}")
    print("\n[demo] IncidentBrief is a typed object (auditable, not a chatbot):")
    print(f"[demo] verdict={brief.verdict} confidence={brief.confidence:.2f} "
          f"actions={len(brief.proposed_actions)} "
          f"has_detection_fix={brief.proposed_detection is not None}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
