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
