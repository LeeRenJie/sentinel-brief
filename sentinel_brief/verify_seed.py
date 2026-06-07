"""Verify the seeded data is searchable in live Splunk AND serves as spike check 6
(real ctx.service.jobs.oneshot SPL against live indexes). Reads creds from .env.

Searches use earliest=0 latest=now (All time) because events are backdated to
2026-05-31.
"""
from __future__ import annotations

import json

from sentinel_brief.splunk_env import live_service


def oneshot(service, spl: str) -> list[dict]:
    import splunklib.results as results

    kwargs = {"earliest_time": "0", "latest_time": "now", "output_mode": "json"}
    stream = service.jobs.oneshot(spl, **kwargs)
    rows = [dict(r) for r in results.JSONResultsReader(stream) if isinstance(r, dict)]
    return rows


def main() -> int:
    service = live_service()
    print("[verify] connected:", service.info.get("serverName"), service.info.get("version"))

    checks = []

    # counts
    auth_n = oneshot(service, "search index=auth | stats count")
    edr_n = oneshot(service, "search index=edr | stats count")
    print("[verify] index=auth count:", auth_n)
    print("[verify] index=edr  count:", edr_n)

    # the svc_backup admin$ chain (the 5 malicious lateral-movement pivots)
    chain = oneshot(
        service,
        "search index=auth user=svc_backup action=logon logon_type=3 share=\"admin$\" "
        "| table _time host user src dest share",
    )
    print(f"[verify] svc_backup admin$ chain rows: {len(chain)}")
    for r in chain:
        print("   ", r.get("_time"), r.get("src"), "->", r.get("dest"), r.get("share"))

    # the 2 malicious EDR signals
    edr_sig = oneshot(
        service,
        "search index=edr signal IN (\"suspicious_download\",\"remote_exec_tool\") "
        "| table _time host user process signal",
    )
    print(f"[verify] malicious EDR signal rows: {len(edr_sig)}")
    for r in edr_sig:
        print("   ", r.get("_time"), r.get("host"), r.get("process"), "::", r.get("signal"))

    # the over-firing detection (svc_backup hits >3 distinct dests)
    overfire = oneshot(
        service,
        "search index=auth action=logon logon_type=3 "
        "| stats dc(dest) as distinct_dests by user | where distinct_dests > 3",
    )
    print("[verify] over-firing detection rows:", overfire)

    # timestamp check: confirm the chain landed at 2026-05-31, not ingest-time
    ts_ok = all(str(r.get("_time", "")).startswith("2026-05-31") for r in chain) and bool(chain)

    checks.append(("auth count == 10", auth_n and auth_n[0].get("count") == "10"))
    checks.append(("edr count == 4", edr_n and edr_n[0].get("count") == "4"))
    checks.append(("svc_backup admin$ chain == 5", len(chain) == 5))
    checks.append(("malicious EDR signals == 2", len(edr_sig) == 2))
    checks.append(("over-fire detection flags svc_backup", any(r.get("user") == "svc_backup" for r in overfire)))
    checks.append(("timestamps preserved 2026-05-31", ts_ok))

    print("\n[verify] RESULTS")
    all_ok = True
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        all_ok = all_ok and ok

    print("\n[verify] SPIKE CHECK 6 (real ctx.service.jobs.oneshot over live SPL):",
          "PASS" if all_ok else "FAIL")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
