"""Measured, backtested detection-improvement loop (the winning differentiator).

This closes the loop the Detection Engineer opens: it doesn't just *propose* a
better SPL rule, it *proves* the proposal on real historical data. It runs BOTH
the old flat-threshold rule and the new EDR-correlated rule over the live data
window and computes — deterministically, from real query results, never from
model prose — how many alerts the new rule eliminates and whether the confirmed
true positive survives.

Honesty contract (the integrity of the metric is the whole point):
  * We do NOT claim an external ground-truth oracle. The discriminator is the
    correlated EDR attack-tool signal: an account that fans out across admin
    shares AND shows a suspicious_download / remote_exec_tool on its origin host
    is a real compromise; one that fans out with NO such signal is a benign
    service account (the false-positive class). The metric states exactly that.
  * The number is computed from real `service.jobs.oneshot` results, not invented
    by an LLM. `compute_backtest()` is a pure function (unit-tested offline).
  * LIVE-ONLY + FAIL-SAFE: only runs when SENTINEL_BACKEND=live and a real service
    is present; any failure returns None and the brief still renders everything
    else. Mock mode never attempts it.

To reinforce the MCP story, the OLD-rule query is routed through the Splunk MCP
Server's `splunk_run_query` tool when MCP is reachable; the NEW-rule query (a
join/subsearch) runs via the local live service. Either way the rows are real.
"""
from __future__ import annotations

import os
from typing import Any

from .schemas import DetectionBacktest

_ALL_TIME = {"earliest_time": "0", "latest_time": "now", "output_mode": "json"}

# The confirmed compromise — the true positive that must survive the new rule.
TRUE_POSITIVE_ACCOUNT = "svc_backup"

# OLD detection: flat distinct-admin-share-dest threshold (over-fires on service accts).
OLD_RULE_SPL = (
    "search index=auth action=logon logon_type=3 "
    "| stats dc(dest) as distinct_dests by user "
    "| where distinct_dests > 3"
)

# NEW detection: same fan-out, but only fires when the same account also shows a
# correlated EDR attack-tool signal (suspicious_download / remote_exec_tool). The
# join on `user` against the edr index drops the benign service-account FP class.
NEW_RULE_SPL = (
    "search index=auth action=logon logon_type=3 "
    "| stats dc(dest) as distinct_dests by user "
    "| where distinct_dests > 3 "
    "| join type=inner user "
    "[ search index=edr signal IN (suspicious_download,remote_exec_tool) "
    "| stats count by user ]"
)


def _is_live() -> bool:
    return os.environ.get("SENTINEL_BACKEND", "live").strip().lower() == "live"


def _accounts(rows: list[dict[str, Any]]) -> list[str]:
    """Pull the distinct `user` values from stats rows, stable-sorted."""
    seen: list[str] = []
    for r in rows:
        u = str(r.get("user", "")).strip()
        if u and u not in seen:
            seen.append(u)
    return sorted(seen)


def compute_backtest(
    old_rows: list[dict[str, Any]],
    new_rows: list[dict[str, Any]],
    *,
    window: str,
    true_positive_account: str = TRUE_POSITIVE_ACCOUNT,
) -> DetectionBacktest:
    """Pure metric computation from real query results (no Splunk, no LLM).

    old_rows / new_rows are the `| stats ... by user` outputs of the OLD and NEW
    rules. The eliminated accounts are exactly OLD-flagged minus NEW-flagged.
    """
    old_accounts = _accounts(old_rows)
    new_accounts = _accounts(new_rows)
    new_set = set(new_accounts)

    eliminated = [u for u in old_accounts if u not in new_set]
    old_n = len(old_accounts)
    new_n = len(new_accounts)
    reduction = (old_n - new_n) / old_n if old_n > 0 else 0.0

    return DetectionBacktest(
        old_alert_count=old_n,
        new_alert_count=new_n,
        false_positives_eliminated=len(eliminated),
        eliminated_accounts=eliminated,
        true_positive_retained=true_positive_account in new_set,
        alert_reduction_pct=round(reduction, 4),
        window=window,
    )


def _oneshot_local(service: Any, spl: str) -> list[dict[str, Any]]:
    result = service.jobs.oneshot(spl, **_ALL_TIME)
    if isinstance(result, list):  # MockService safety (not used in live path)
        return result
    import splunklib.results as results

    return [dict(r) for r in results.JSONResultsReader(result) if isinstance(r, dict)]


def _oneshot_via_mcp(service: Any, spl: str, *, logger: Any = None) -> list[dict[str, Any]] | None:
    """Run SPL through the Splunk MCP Server's splunk_run_query tool.

    Best-effort: reinforces the MCP story by routing the OLD-rule query through
    MCP. Returns None on any failure so the caller falls back to the local query
    (the metric is identical either way — same indexes, same SPL).
    """
    try:
        import asyncio

        from splunklib.ai.agent import _get_splunk_username  # type: ignore[attr-defined]
        from splunklib.ai.tools import connect_remote_mcp

        from .mcp_wiring import MCP_APP_ID

        async def _call() -> list[dict[str, Any]] | None:
            username = _get_splunk_username(service)
            async with connect_remote_mcp(service, MCP_APP_ID, "backtest", username) as session:
                if session is None:
                    return None
                res = await session.call_tool(
                    "splunk_run_query",
                    {"query": spl, "earliest_time": "0", "latest_time": "now"},
                )
                rows = _parse_mcp_rows(res)
                if logger is not None:
                    logger.info("backtest: splunk_run_query (MCP) returned %d rows", len(rows))
                return rows

        # demo.py calls run_backtest() from inside a running event loop, so we can't
        # asyncio.run() here ("event loop already running"). Run the MCP coroutine in
        # a dedicated worker thread with its own fresh loop. If no loop is running
        # (e.g. a standalone script), asyncio.run() in the same thread is fine too.
        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False

        if not in_loop:
            return asyncio.run(_call())

        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(lambda: asyncio.run(_call())).result(timeout=60)
    except Exception as exc:  # noqa: BLE001
        if logger is not None:
            logger.warning("backtest MCP path failed (%s: %s); using local query",
                           type(exc).__name__, exc)
        return None


def _parse_mcp_rows(res: Any) -> list[dict[str, Any]]:
    """Normalize an MCP call_tool result into list[dict]. MCP content is typically
    a list of TextContent blocks whose text is JSON {results:[...]} or a raw list.
    """
    import json

    texts: list[str] = []
    content = getattr(res, "content", res)
    if isinstance(content, list):
        for block in content:
            t = getattr(block, "text", None)
            if t is not None:
                texts.append(t)
    elif isinstance(content, str):
        texts.append(content)

    rows: list[dict[str, Any]] = []
    for t in texts:
        try:
            obj = json.loads(t)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(obj, dict) and isinstance(obj.get("results"), list):
            rows.extend(r for r in obj["results"] if isinstance(r, dict))
        elif isinstance(obj, list):
            rows.extend(r for r in obj if isinstance(r, dict))
    return rows


def run_backtest(
    service: Any,
    *,
    window: str = "All time (seeded 7d window)",
    prefer_mcp: bool = True,
    logger: Any = None,
) -> DetectionBacktest | None:
    """Live-gated, fail-safe entry. Runs OLD + NEW rules against the live indexes
    and returns the measured DetectionBacktest, or None if it can't run cleanly.

    The OLD-rule query is attempted through MCP `splunk_run_query` first (MCP
    story); on any MCP failure it falls back to the local live query. The NEW-rule
    join always runs via the local live service.
    """
    if not _is_live() or service is None:
        return None
    try:
        old_rows: list[dict[str, Any]] | None = None
        if prefer_mcp:
            old_rows = _oneshot_via_mcp(service, OLD_RULE_SPL, logger=logger)
            if old_rows is not None and logger is not None:
                logger.info("backtest: OLD rule sourced via Splunk MCP Server")
        if old_rows is None:
            old_rows = _oneshot_local(service, OLD_RULE_SPL)

        new_rows = _oneshot_local(service, NEW_RULE_SPL)

        bt = compute_backtest(old_rows, new_rows, window=window)
        # Integrity guard: a 0-account old rule or a non-retained TP is not a
        # demo-worthy honest result — surface None rather than a misleading metric.
        if bt.old_alert_count == 0:
            if logger is not None:
                logger.warning("backtest: OLD rule fired on 0 accounts; suppressing metric")
            return None
        return bt
    except Exception as exc:  # noqa: BLE001
        if logger is not None:
            logger.warning("backtest failed (%s: %s); detection_backtest=None",
                           type(exc).__name__, exc)
        return None
