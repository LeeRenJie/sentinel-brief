"""Offline unit tests (no Vertex) — schema validity + renderer + mock service.
Deterministic tester gate that does not burn API calls."""
from sentinel_brief.mock_service import MockService, SEED_AUTH_EVENTS
from sentinel_brief.render import render_brief
from sentinel_brief.schemas import (
    BlastRadiusEntity,
    IncidentBrief,
    ProposedAction,
    ProposedDetection,
    TimelineEvent,
)


def _sample_brief() -> IncidentBrief:
    return IncidentBrief(
        detection_name="Excessive Admin-Share Logons by Single Account",
        verdict="true_positive",
        severity="high",
        confidence=0.95,
        summary="Compromised svc_backup pivots from WKS-014 to 8 hosts.",
        mitre_techniques=["T1021.002", "T1078"],
        timeline=[
            TimelineEvent(timestamp="2026-05-31T02:11:04Z", source_index="auth",
                          host="WKS-014", user="svc_backup",
                          description="Admin-share logon to FS-01"),
        ],
        blast_radius=[
            BlastRadiusEntity(entity="WKS-014", entity_type="host",
                              role="origin", exposure_rank=1),
        ],
        proposed_actions=[
            ProposedAction(action_id="isolate-WKS-014", title="Isolate host WKS-014",
                           rationale="origin host", tool="isolate_host"),
        ],
        proposed_detection=ProposedDetection(
            problem="over-fires on service accounts",
            current_spl="index=auth | stats dc(dest) by user | where dc>3",
            proposed_spl="... EDR-correlated ...",
            spl_diff="--- a\n+++ b\n+ gate on edr signal",
            expected_effect="removes svc-account FP class, keeps TP",
        ),
    )


def test_brief_schema_roundtrips():
    brief = _sample_brief()
    dumped = brief.model_dump_json()
    restored = IncidentBrief.model_validate_json(dumped)
    assert restored.verdict == "true_positive"
    assert restored.proposed_detection is not None
    assert restored.confidence == 0.95


def test_action_defaults_are_human_in_the_loop():
    a = ProposedAction(action_id="x", title="t", rationale="r", tool="isolate_host")
    assert a.dry_run is True
    assert a.requires_approval is True


def test_render_contains_wow_and_verdict():
    out = render_brief(_sample_brief())
    assert "TRUE POSITIVE" in out
    assert "PROPOSED DETECTION FIX" in out  # the wow is rendered
    assert "MITRE ATT&CK: T1021.002" in out
    assert "human approval required" in out


def test_mock_service_username_and_oneshot():
    svc = MockService()
    body = svc.get(path_segment="authentication/current-context", output_mode="json").body
    assert "sentinel-analyst" in body
    rows = svc.jobs.oneshot("search index=auth action=logon logon_type=3")
    # the malicious lateral-movement chain is the prefix; benign-fanout FP-class
    # service accounts follow (added for the measured detection backtest).
    assert rows[: len(SEED_AUTH_EVENTS)] == SEED_AUTH_EVENTS
    assert len(rows) > len(SEED_AUTH_EVENTS)
