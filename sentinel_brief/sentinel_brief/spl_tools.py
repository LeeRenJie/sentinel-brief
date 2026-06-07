"""Local SPL tools (Developer Tools bonus lane). @registry.tool() + ctx.service.

These call ctx.service.jobs.oneshot(spl). In mock-mode the MockService returns
canned seeded rows; at Lane-A merge the SAME tool runs against real index data
with no change (B5 swap). Registered tools are auto-exposed to the Correlator.

NOTE: full agent tool-wiring (passing ToolSettings/registry into Agent) is
validated against the live SDK in spike check 6 once Splunk is up. Mock-mode runs
the spine via the subagents' own reasoning over seeded context; this module is the
real-SPL path staged and ready.
"""
from __future__ import annotations

from typing import Any

from splunklib.ai.registry import ToolContext, ToolRegistry

registry = ToolRegistry()


def _rows(result: Any) -> list[dict[str, Any]]:
    """Normalize oneshot output (mock returns list[dict]; real returns a reader)."""
    if isinstance(result, list):
        return result
    # real splunklib results reader -> list of dict-like
    try:
        from splunklib import results as _r

        return [dict(item) for item in _r.JSONResultsReader(result) if isinstance(item, dict)]
    except Exception:
        return [dict(item) for item in result]


@registry.tool()
def search_auth_index(query_window: str, ctx: ToolContext) -> list[dict[str, Any]]:
    """Search the auth index for logon events (SMB/admin$ lateral movement).

    query_window: a human time window, e.g. 'last 30 minutes'.
    """
    ctx.logger.info("search_auth_index window=%s", query_window)
    spl = (
        "search index=auth action=logon logon_type=3 "
        "| table _time host user src dest share"
    )
    return _rows(ctx.service.jobs.oneshot(spl))


@registry.tool()
def search_edr_index(query_window: str, ctx: ToolContext) -> list[dict[str, Any]]:
    """Search the edr index for suspicious process/download signals.

    query_window: a human time window, e.g. 'last 30 minutes'.
    """
    ctx.logger.info("search_edr_index window=%s", query_window)
    spl = (
        "search index=edr "
        "| table _time host user process cmdline signal"
    )
    return _rows(ctx.service.jobs.oneshot(spl))


@registry.tool()
def blast_radius(seed_host: str, ctx: ToolContext) -> list[dict[str, Any]]:
    """Compute hosts/accounts reachable from a seed host via lateral movement.

    seed_host: the origin host, e.g. 'WKS-014'.
    """
    ctx.logger.info("blast_radius seed_host=%s", seed_host)
    spl = (
        f"search index=auth src={seed_host} action=logon logon_type=3 "
        "| stats values(dest) as pivoted_to values(user) as accounts by src"
    )
    return _rows(ctx.service.jobs.oneshot(spl))


if __name__ == "__main__":
    registry.run()
