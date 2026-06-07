"""Offline tests for the measured detection-backtest metric (zero Splunk/Vertex).

We feed `compute_backtest` known OLD/NEW rule result rows and assert the math, the
eliminated-accounts logic, the TP-retained flag, and the render climax. We also
assert the live-gating/fail-safe of `run_backtest` (mock mode -> None, no service
-> None) without touching Splunk.
"""
from __future__ import annotations

import os

import pytest

from sentinel_brief.backtest import compute_backtest, run_backtest
from sentinel_brief.render import render_brief
from sentinel_brief.schemas import DetectionBacktest, IncidentBrief


# The canonical seeded result shape: OLD fires on 4, NEW fires on 1 (svc_backup).
OLD_ROWS = [
    {"user": "svc_backup", "distinct_dests": "5"},
    {"user": "svc_monitor", "distinct_dests": "4"},
    {"user": "svc_patch", "distinct_dests": "4"},
    {"user": "svc_vuln", "distinct_dests": "4"},
]
NEW_ROWS = [
    {"user": "svc_backup", "distinct_dests": "5", "count": "1"},
]


def test_metric_math_matches_seeded_scenario():
    bt = compute_backtest(OLD_ROWS, NEW_ROWS, window="last 7d")
    assert bt.old_alert_count == 4
    assert bt.new_alert_count == 1
    assert bt.false_positives_eliminated == 3
    assert bt.alert_reduction_pct == 0.75
    assert bt.true_positive_retained is True
    assert bt.window == "last 7d"


def test_eliminated_accounts_are_old_minus_new():
    bt = compute_backtest(OLD_ROWS, NEW_ROWS, window="w")
    assert set(bt.eliminated_accounts) == {"svc_monitor", "svc_patch", "svc_vuln"}
    # svc_backup (the TP) is NOT in the eliminated set
    assert "svc_backup" not in bt.eliminated_accounts


def test_tp_lost_is_detected():
    # NEW rule that wrongly drops svc_backup -> TP not retained
    bt = compute_backtest(OLD_ROWS, [{"user": "svc_monitor"}], window="w")
    assert bt.true_positive_retained is False


def test_no_division_by_zero_when_old_empty():
    bt = compute_backtest([], [], window="w")
    assert bt.old_alert_count == 0
    assert bt.alert_reduction_pct == 0.0


def test_dedupes_multiple_rows_per_account():
    # stats-by-user should be one row/user, but guard against dupes anyway
    old = [{"user": "svc_backup"}, {"user": "svc_backup"}, {"user": "svc_patch"}]
    bt = compute_backtest(old, [{"user": "svc_backup"}], window="w")
    assert bt.old_alert_count == 2
    assert bt.eliminated_accounts == ["svc_patch"]


def test_run_backtest_returns_none_in_mock_mode(monkeypatch):
    monkeypatch.setenv("SENTINEL_BACKEND", "mock")
    assert run_backtest(object(), logger=None) is None


def test_run_backtest_returns_none_without_service(monkeypatch):
    monkeypatch.setenv("SENTINEL_BACKEND", "live")
    assert run_backtest(None, logger=None) is None


def test_backtest_renders_as_climax():
    bt = compute_backtest(OLD_ROWS, NEW_ROWS, window="last 7d")
    brief = IncidentBrief(
        detection_name="X", verdict="true_positive", severity="high",
        confidence=1.0, summary="s", detection_backtest=bt,
    )
    out = render_brief(brief, color=False)
    assert "BACKTEST ON REAL DATA" in out
    assert "old rule 4 alerts (3 false)" in out
    assert "75% fewer alerts" in out
    assert "true positive RETAINED" in out
    # the dropped benign accounts are named honestly
    assert "svc_monitor" in out and "svc_patch" in out and "svc_vuln" in out


def test_brief_without_backtest_still_renders():
    brief = IncidentBrief(
        detection_name="X", verdict="true_positive", severity="high",
        confidence=1.0, summary="s", detection_backtest=None,
    )
    out = render_brief(brief, color=False)
    assert "BACKTEST ON REAL DATA" not in out  # degrades cleanly
    assert "SENTINEL BRIEF" in out


def test_backtest_schema_bounds():
    with pytest.raises(Exception):
        DetectionBacktest(
            old_alert_count=-1, new_alert_count=0, false_positives_eliminated=0,
            true_positive_retained=True, alert_reduction_pct=0.0, window="w",
        )
    with pytest.raises(Exception):
        DetectionBacktest(
            old_alert_count=4, new_alert_count=1, false_positives_eliminated=3,
            true_positive_retained=True, alert_reduction_pct=1.5, window="w",
        )
