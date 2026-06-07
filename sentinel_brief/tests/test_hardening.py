"""Expanded OFFLINE coverage — schema validation, render snapshot assertions,
mock-service determinism, and seed-CSV no-drift. NO Vertex / network calls.

These import the package (cheap — config builds models lazily) but NEVER call
make_model / run_sentinel_brief, so they burn zero API quota.
"""
import csv
import re
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel_brief.mock_service import (
    SEED_AUTH_EVENTS,
    SEED_EDR_EVENTS,
    MockService,
)
from sentinel_brief.render import render_brief
from sentinel_brief.schemas import (
    BlastRadiusEntity,
    IncidentBrief,
    ProposedAction,
    ProposedDetection,
    TimelineEvent,
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_REPO = Path(__file__).resolve().parents[2]  # splunk-hackathon/
_SEED = _REPO / "seed_data"


def _full_brief() -> IncidentBrief:
    return IncidentBrief(
        detection_name="Excessive Admin-Share Logons by Single Account",
        verdict="true_positive",
        severity="high",
        confidence=0.95,
        summary="Compromised svc_backup pivots from WKS-014 across 5 admin shares.",
        mitre_techniques=["T1021.002", "T1078", "T1059.001"],
        timeline=[
            TimelineEvent(timestamp="2026-05-31T02:08:12Z", source_index="edr",
                          host="WKS-014", user="jdoe",
                          description="Suspicious PowerShell download"),
            TimelineEvent(timestamp="2026-05-31T02:11:04Z", source_index="auth",
                          host="WKS-014", user="svc_backup",
                          description="Admin-share logon to FS-01"),
        ],
        blast_radius=[
            BlastRadiusEntity(entity="WKS-014", entity_type="host",
                              role="origin", exposure_rank=1),
            BlastRadiusEntity(entity="FS-01", entity_type="host",
                              role="pivoted-to", exposure_rank=2),
        ],
        proposed_actions=[
            ProposedAction(action_id="isolate-WKS-014", title="Isolate host WKS-014",
                           rationale="origin host of the pivot", tool="isolate_host"),
        ],
        proposed_detection=ProposedDetection(
            problem="over-fires on legitimate service accounts",
            current_spl="index=auth action=logon logon_type=3\n| stats dc(dest) by user\n| where dc>3",
            proposed_spl="index=auth action=logon logon_type=3\n| join host [search index=edr signal=*]\n| where dc>3",
            spl_diff="--- current\n+++ proposed\n- | where dc>3\n+ | join host [search index=edr signal=*]\n+ | where dc>3",
            expected_effect="removes svc-account FP class, keeps the true positive",
        ),
    )


# ---------------- schema validation ----------------

def test_confidence_bounds_enforced():
    with pytest.raises(ValidationError):
        IncidentBrief(detection_name="d", verdict="true_positive", severity="high",
                      confidence=1.5, summary="x")
    with pytest.raises(ValidationError):
        IncidentBrief(detection_name="d", verdict="true_positive", severity="high",
                      confidence=-0.1, summary="x")


def test_verdict_and_severity_literals_enforced():
    with pytest.raises(ValidationError):
        IncidentBrief(detection_name="d", verdict="maybe", severity="high",
                      confidence=0.5, summary="x")
    with pytest.raises(ValidationError):
        IncidentBrief(detection_name="d", verdict="true_positive", severity="urgent",
                      confidence=0.5, summary="x")


def test_min_length_fields_reject_empty():
    with pytest.raises(ValidationError):
        IncidentBrief(detection_name="d", verdict="true_positive", severity="high",
                      confidence=0.5, summary="")
    with pytest.raises(ValidationError):
        TimelineEvent(timestamp="t", source_index="auth", host="h", description="")


def test_exposure_rank_must_be_positive():
    with pytest.raises(ValidationError):
        BlastRadiusEntity(entity="h", entity_type="host", role="origin", exposure_rank=0)


def test_proposed_detection_requires_core_fields():
    with pytest.raises(ValidationError):
        ProposedDetection(problem="", proposed_spl="x", expected_effect="y")
    with pytest.raises(ValidationError):
        ProposedDetection(problem="p", proposed_spl="", expected_effect="y")


def test_full_brief_roundtrips_all_sections():
    brief = _full_brief()
    restored = IncidentBrief.model_validate_json(brief.model_dump_json())
    assert restored.verdict == "true_positive"
    assert len(restored.timeline) == 2
    assert len(restored.blast_radius) == 2
    assert restored.proposed_detection is not None
    assert len(restored.mitre_techniques) == 3


# ---------------- render snapshot-style assertions ----------------

def test_render_has_all_sections_plain():
    out = render_brief(_full_brief(), color=False)
    assert "SENTINEL BRIEF" in out
    assert "TRUE POSITIVE" in out
    assert "CONFIDENCE: 95%" in out
    assert "MITRE ATT&CK: T1021.002" in out
    assert "SMB/Windows Admin Shares" in out  # static name mapping
    assert "TIMELINE (multi-index)" in out
    assert "BLAST RADIUS (ranked by exposure)" in out
    assert "#1 WKS-014" in out  # ranked origin row
    assert "human approval required" in out
    assert "[ ] Isolate host WKS-014" in out
    assert "rationale:" in out
    assert "PROPOSED DETECTION FIX" in out  # the wow climax


def test_render_diff_has_gutters():
    out = render_brief(_full_brief(), color=False)
    # the diff +/- lines survive into the rendered output
    assert "+ | join host [search index=edr signal=*]" in out
    assert "- | where dc>3" in out


def test_render_plain_has_no_ansi_codes():
    out = render_brief(_full_brief(), color=False)
    assert _ANSI.search(out) is None, "color=False must not emit ANSI escapes"


def test_render_color_emits_ansi():
    out = render_brief(_full_brief(), color=True)
    assert _ANSI.search(out) is not None


def test_render_degrades_without_detection_fix():
    brief = _full_brief()
    brief.proposed_detection = None
    out = render_brief(brief, color=False)
    assert "PROPOSED DETECTION FIX" not in out  # header gone, no crash


def test_render_handles_empty_sections():
    brief = IncidentBrief(detection_name="d", verdict="inconclusive", severity="low",
                          confidence=0.3, summary="nothing correlated")
    out = render_brief(brief, color=False)  # must not raise
    assert "INCONCLUSIVE" in out
    assert "no timeline events" in out
    assert "no implicated entities" in out
    assert "no proposed actions" in out


def test_render_diff_synthesized_when_no_unified_diff():
    brief = _full_brief()
    brief.proposed_detection.spl_diff = ""  # force synth from current/proposed
    out = render_brief(brief, color=False)
    assert "- index=auth action=logon" in out  # current lines guttered as removals
    assert "+ index=auth action=logon" in out  # proposed lines guttered as adds


# ---------------- mock-service determinism ----------------

def test_oneshot_routing_deterministic():
    from sentinel_brief.mock_service import SEED_BENIGN_FANOUT_AUTH

    svc = MockService()
    for _ in range(3):
        # auth path now includes the benign-fanout service accounts (the FP class)
        # so mock-mode auth queries reflect the seeded reality. The malicious chain
        # is still present (prefix), zero drift.
        auth = svc.jobs.oneshot("search index=auth logon_type=3")
        assert auth == SEED_AUTH_EVENTS + SEED_BENIGN_FANOUT_AUTH
        assert auth[: len(SEED_AUTH_EVENTS)] == SEED_AUTH_EVENTS
        assert svc.jobs.oneshot("search index=edr powershell") == SEED_EDR_EVENTS
        assert svc.jobs.oneshot("| makeresults") == [{"_time": "now", "count": "1"}]
        union = svc.jobs.oneshot("search index=* | stats count")
        assert union == SEED_AUTH_EVENTS + SEED_BENIGN_FANOUT_AUTH + SEED_EDR_EVENTS


def test_mock_service_username():
    svc = MockService()
    body = svc.get(path_segment="authentication/current-context",
                   output_mode="json").body
    assert "sentinel-analyst" in body
    other = svc.get(path_segment="something/else").body
    assert "entry" in other  # unknown path returns empty entry list, no crash


def test_seed_constants_consistent():
    assert SEED_AUTH_EVENTS and SEED_EDR_EVENTS
    for e in SEED_AUTH_EVENTS:
        for k in ("_time", "index", "host", "user", "action", "dest"):
            assert k in e, f"auth seed event missing {k}"
        assert e["index"] == "auth"
    for e in SEED_EDR_EVENTS:
        for k in ("_time", "index", "host", "user", "process", "signal"):
            assert k in e, f"edr seed event missing {k}"
        assert e["index"] == "edr"
    # the malicious account and origin host are the scenario invariants
    assert any(e["user"] == "svc_backup" for e in SEED_AUTH_EVENTS)
    assert all(e["src"] == "WKS-014" for e in SEED_AUTH_EVENTS)


# ---------------- detection-engineer (the WOW) golden-shape ----------------
# These assert the SHAPE the hardened detection_engineer prompt must produce.
# They run fully OFFLINE on a hand-authored ProposedDetection that mirrors the
# expected model output — they validate the render/contract, NOT a live model.

def _golden_detection() -> ProposedDetection:
    """The reference detection fix the hardened prompt is engineered to emit:
    keeps the admin-share fan-out (the TP), adds an EDR-signal correlation that
    removes the service-account FP class, presented as a unified diff."""
    return ProposedDetection(
        problem=(
            "The current rule alerts on distinct admin-share destination count "
            "alone, so it cannot distinguish a legitimate backup service account "
            "from a compromised one and over-fires on svc_backup/svc_monitor."
        ),
        current_spl=(
            "index=auth action=logon logon_type=3\n"
            "| stats dc(dest) as distinct_dests by user\n"
            "| where distinct_dests > 3"
        ),
        proposed_spl=(
            "index=auth action=logon logon_type=3 share=\"admin$\"\n"
            "| stats dc(dest) as distinct_dests values(dest) as dests "
            "min(_time) as first by user host\n"
            "| where distinct_dests > 3\n"
            "| join type=inner host\n"
            "    [ search index=edr signal IN (\"suspicious_download\",\"remote_exec_tool\")\n"
            "      | stats count as edr_signals by host ]\n"
            "| where edr_signals > 0"
        ),
        spl_diff=(
            "--- current detection\n"
            "+++ proposed detection\n"
            "  index=auth action=logon logon_type=3\n"
            "- | stats dc(dest) as distinct_dests by user\n"
            "- | where distinct_dests > 3\n"
            "+ index=auth action=logon logon_type=3 share=\"admin$\"\n"
            "+ | stats dc(dest) as distinct_dests by user host\n"
            "+ | where distinct_dests > 3\n"
            "+ | join type=inner host\n"
            "+     [ search index=edr signal IN (\"suspicious_download\",\"remote_exec_tool\")\n"
            "+       | stats count as edr_signals by host ]\n"
            "+ | where edr_signals > 0"
        ),
        expected_effect=(
            "Eliminates the recurring svc_backup/svc_monitor false positives (the "
            "entire service-account FP class) while still firing on the WKS-014 "
            "compromise, which alone carries the EDR attack-tool signal."
        ),
    )


def test_golden_detection_keeps_tp_removes_fp_class():
    d = _golden_detection()
    # The fix correlates against the EDR discriminator (the TP-vs-FP signal).
    assert "index=edr" in d.proposed_spl
    assert "suspicious_download" in d.proposed_spl
    assert "remote_exec_tool" in d.proposed_spl
    # It KEEPS the admin-share fan-out logic that catches the real attack.
    assert "distinct_dests" in d.proposed_spl
    assert "admin$" in d.proposed_spl
    # The effect explicitly names removing the FP class without losing the TP.
    eff = d.expected_effect.lower()
    assert "false positive" in eff or "fp class" in eff
    assert "wks-014" in eff


def test_golden_detection_renders_as_unified_diff():
    brief = _full_brief()
    brief.proposed_detection = _golden_detection()
    out = render_brief(brief, color=False)
    # Unified-diff headers and gutters survive into the brief.
    assert "--- current detection" in out
    assert "+++ proposed detection" in out
    # The EDR-correlation addition shows as +-gutter lines (the fix).
    assert "+ | join type=inner host" in out
    assert "+       | stats count as edr_signals by host" in out
    # The removed flat-threshold line shows as a --gutter line.
    assert "- | where distinct_dests > 3" in out


def test_golden_detection_diff_is_balanced_and_real_spl():
    """The diff must add more than it removes (it tightens, not guts) and use
    only real SPL verbs — no pseudo-code leaks into the centerpiece."""
    d = _golden_detection()
    diff_lines = d.spl_diff.splitlines()
    adds = [l for l in diff_lines if l.lstrip().startswith("+") and not l.startswith("+++")]
    removes = [l for l in diff_lines if l.lstrip().startswith("-") and not l.startswith("---")]
    assert adds and removes
    assert len(adds) >= len(removes)  # it tightens the rule, doesn't delete it
    # real SPL verbs present; no obvious pseudo-code tokens
    joined = d.proposed_spl.lower()
    assert any(v in joined for v in ("stats", "where", "join", "eval", "search"))
    assert "todo" not in joined and "pseudo" not in joined and "<...>" not in joined


# ---------------- seed CSV: no-drift guarantee ----------------

def test_seed_csvs_match_seed_constants():
    """The committed CSVs must contain the seed scenario rows exactly (no drift).
    Reads files offline; regenerates if missing."""
    auth_csv = _SEED / "auth.csv"
    edr_csv = _SEED / "edr.csv"
    if not (auth_csv.exists() and edr_csv.exists()):
        subprocess.run([sys.executable, str(_SEED / "generate_seed_csvs.py")],
                       check=True)

    with auth_csv.open(encoding="utf-8") as fh:
        auth_rows = list(csv.DictReader(fh))
    with edr_csv.open(encoding="utf-8") as fh:
        edr_rows = list(csv.DictReader(fh))

    mal_auth = [r for r in auth_rows if r["scenario"] == "lateral-movement"]
    mal_edr = [r for r in edr_rows if r["scenario"] == "lateral-movement"]

    # counts match the seed exactly
    assert len(mal_auth) == len(SEED_AUTH_EVENTS)
    assert len(mal_edr) == len(SEED_EDR_EVENTS)

    # every seeded auth event appears verbatim on its key fields
    seed_auth_keys = {(e["_time"], e["host"], e["user"], e["dest"])
                      for e in SEED_AUTH_EVENTS}
    csv_auth_keys = {(r["_time"], r["host"], r["user"], r["dest"])
                     for r in mal_auth}
    assert seed_auth_keys == csv_auth_keys

    seed_edr_keys = {(e["_time"], e["host"], e["user"], e["process"])
                     for e in SEED_EDR_EVENTS}
    csv_edr_keys = {(r["_time"], r["host"], r["user"], r["process"])
                    for r in mal_edr}
    assert seed_edr_keys == csv_edr_keys
