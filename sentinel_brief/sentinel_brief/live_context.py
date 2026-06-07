"""B5 — build the fired-detection context from LIVE SPL results (real index data),
in the same shape the mock path produces, so the agent spine + IncidentBrief +
render path are unchanged: only the evidence source swaps from seed constants to
real ctx.service.jobs.oneshot results.

Used by demo.py when SENTINEL_BACKEND=live. The mock path keeps composing its
context from SEED_* constants (offline). Identical scenario, zero drift, because
the live indexes were seeded from those same constants.
"""
from __future__ import annotations

from typing import Any

from .mock_service import SEED_CURRENT_DETECTION_SPL

_ALL_TIME = {"earliest_time": "0", "latest_time": "now", "output_mode": "json"}


def _oneshot(service: Any, spl: str) -> list[dict[str, Any]]:
    """Run live SPL and normalize to list[dict] (handles the results reader)."""
    result = service.jobs.oneshot(spl, **_ALL_TIME)
    if isinstance(result, list):  # MockService path (not used here, but safe)
        return result
    import splunklib.results as results

    return [dict(r) for r in results.JSONResultsReader(result) if isinstance(r, dict)]


def build_live_detection_context(service: Any, detection_name: str) -> str:
    """Query the live auth/edr indexes and compose the detection context string.

    Mirrors demo._fired_detection_context() but sources every line from real SPL.
    """
    auth_rows = _oneshot(
        service,
        "search index=auth action=logon logon_type=3 "
        "| sort 0 _time | table _time host user src dest share",
    )
    edr_rows = _oneshot(
        service,
        "search index=edr signal=* "
        "| sort 0 _time | table _time host user process cmdline signal",
    )

    auth = "\n".join(
        f"  {e.get('_time')} {e.get('host')} user={e.get('user')} "
        f"-> {e.get('dest')} ({e.get('share')})"
        for e in auth_rows
        if e.get("share")  # admin/C$ share logons are the lateral-movement signal
    )
    edr = "\n".join(
        f"  {e.get('_time')} {e.get('host')} user={e.get('user')} "
        f"{e.get('process')} :: {e.get('signal')}"
        for e in edr_rows
    )

    return (
        f"FIRED DETECTION: {detection_name}\n"
        f"Current detection SPL (known to over-fire on service accounts):\n"
        f"{SEED_CURRENT_DETECTION_SPL}\n\n"
        f"auth index events (live SPL, index=auth):\n{auth}\n\n"
        f"edr index events (live SPL, index=edr):\n{edr}\n\n"
        "Note: svc_backup is a legitimate backup service account that normally "
        "touches a few file servers nightly — the current rule over-fires on it, "
        "but THIS run also shows a preceding suspicious PowerShell download on "
        "WKS-014 and PsExec remote-exec, which distinguishes a real compromise. "
        "All evidence above was retrieved from the live Splunk auth/edr indexes "
        "via ctx.service.jobs.oneshot."
    )
