"""F2 — the typed incident brief. The deliverable + demo object.

The whole product collapses a fired detection into ONE auditable, typed object
(not a chat transcript). An AI/ML judge can read and audit this. Verified in the
Day-0 spike: Gemini 2.5-pro fills this schema cleanly via output_schema.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


Verdict = Literal["true_positive", "false_positive", "inconclusive"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class TimelineEvent(BaseModel):
    """One event on the multi-index incident timeline (Correlator output)."""

    timestamp: str = Field(description="ISO-8601 event time.")
    source_index: str = Field(description="Splunk index the event came from, e.g. 'auth' or 'edr'.")
    host: str = Field(description="Host the event occurred on.")
    user: str = Field(default="", description="Associated user/account, if any.")
    description: str = Field(min_length=1, description="What happened, one line.")


class BlastRadiusEntity(BaseModel):
    """An entity (host/account) implicated in the incident, ranked by exposure.

    Degradable per scope-cut #3: render as a ranked list (this) instead of a graph.
    """

    entity: str = Field(description="Host or account identifier.")
    entity_type: Literal["host", "account", "process", "ip"] = Field(description="Kind of entity.")
    role: str = Field(description="How it's implicated, e.g. 'origin', 'pivoted-to', 'credential-used'.")
    exposure_rank: int = Field(ge=1, description="1 = most exposed/central to the incident.")


class ProposedAction(BaseModel):
    """A SOP-grounded containment action awaiting human approval (Responder output)."""

    action_id: str = Field(description="Stable id, e.g. 'isolate-WKS-014'.")
    title: str = Field(min_length=1, description="Human-readable action, e.g. 'Isolate host WKS-014'.")
    rationale: str = Field(min_length=1, description="Why this action, grounded in the evidence.")
    tool: str = Field(description="Tool/endpoint that would execute it (MCP tool name or local SPL).")
    dry_run: bool = Field(default=True, description="Default true — never auto-executes. Human approves.")
    requires_approval: bool = Field(default=True, description="Human-in-the-loop gate (always true).")


class ProposedDetection(BaseModel):
    """THE WOW (F3, non-cuttable) — Detection Engineer's self-improving SPL fix.

    The proposed SPL rule change that would have caught this cleanly / removed the
    false-positive class. This is what no first-party triage agent ships.
    """

    problem: str = Field(min_length=1, description="What the current detection got wrong (miss or over-fire).")
    current_spl: str = Field(default="", description="The existing detection SPL, if known.")
    proposed_spl: str = Field(min_length=1, description="The proposed replacement/added SPL detection.")
    spl_diff: str = Field(default="", description="Unified-diff-style summary of the change for the brief.")
    expected_effect: str = Field(min_length=1, description="e.g. 'removes ~80% of svc-account FPs while keeping TP'.")


class DetectionBacktest(BaseModel):
    """Measured proof the proposed SPL fix works — computed deterministically from
    real query results against the live indexes, NOT from model prose.

    The OLD rule and the NEW (EDR-correlated) rule are both executed over the data
    window. The benign service accounts the OLD rule flags but the NEW rule drops
    are genuine false positives: they show admin-share fan-out but NO correlated
    attack-tool EDR signal — that correlation IS the honest discriminator. We do
    not claim an external ground-truth oracle; we state exactly that.
    """

    old_alert_count: int = Field(ge=0, description="Accounts the OLD flat-threshold rule fires on.")
    new_alert_count: int = Field(ge=0, description="Accounts the NEW EDR-correlated rule fires on.")
    false_positives_eliminated: int = Field(
        ge=0, description="OLD-flagged accounts the NEW rule correctly drops (no correlated EDR attack signal)."
    )
    eliminated_accounts: list[str] = Field(
        default_factory=list,
        description="The benign service accounts dropped by the new rule (the eliminated FP class).",
    )
    true_positive_retained: bool = Field(
        description="The confirmed compromise still appears in the NEW rule's results."
    )
    alert_reduction_pct: float = Field(
        ge=0.0, le=1.0, description="(old - new) / old — fraction of alerts eliminated."
    )
    window: str = Field(description="The data window the backtest ran over, e.g. 'last 7d' or 'All time'.")


class IncidentBrief(BaseModel):
    """The single scannable, auditable brief. Reads in 10s. F2 deliverable.

    verdict banner -> timeline -> blast-radius -> actions(approve) -> detection diff.
    """

    detection_name: str = Field(description="The fired detection/correlation-search name.")
    verdict: Verdict = Field(description="Adjudicated verdict for the detection.")
    severity: Severity = Field(description="Adjudicated severity.")
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 adjudication confidence.")
    summary: str = Field(min_length=1, description="One-line analyst summary (the headline).")
    mitre_techniques: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs, e.g. ['T1021.002', 'T1078']."
    )
    timeline: list[TimelineEvent] = Field(
        default_factory=list, description="Multi-index event timeline, chronological."
    )
    blast_radius: list[BlastRadiusEntity] = Field(
        default_factory=list, description="Implicated entities ranked by exposure."
    )
    proposed_actions: list[ProposedAction] = Field(
        default_factory=list, description="SOP-grounded containment actions, human-approved."
    )
    proposed_detection: ProposedDetection | None = Field(
        default=None, description="THE WOW — self-improving SPL detection fix."
    )
    detection_backtest: DetectionBacktest | None = Field(
        default=None,
        description="MEASURED proof the fix works — old vs new rule on real data. "
        "Null in mock mode or if the live backtest can't run (fail-safe).",
    )
