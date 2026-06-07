"""Deterministically generate seed CSVs for the `auth` and `edr` Splunk indexes.

SINGLE SOURCE OF TRUTH: the rows here are derived strictly from
`sentinel_brief.mock_service.SEED_AUTH_EVENTS` / `SEED_EDR_EVENTS` — the exact
seeded lateral-movement scenario the mock demo runs. This guarantees the
live-Splunk demo (A3 ingest) matches the mock demo with ZERO scenario drift.

We additionally emit a small set of clearly-labelled BENIGN background-noise rows
(normal logons by unrelated users) so the live index looks realistic and so the
over-firing detection has a believable baseline. The benign rows DO NOT touch the
malicious chain (svc_backup / WKS-014 / jdoe) and do not change the detection's
behaviour. They carry scenario="benign-noise" so they are trivially separable.

Run (from repo root, with the project venv):
    sentinel_brief/.venv/Scripts/python.exe seed_data/generate_seed_csvs.py

Outputs (overwritten deterministically):
    seed_data/auth.csv
    seed_data/edr.csv
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

# Make the inner package importable whether run from repo root or seed_data/.
_HERE = Path(__file__).resolve().parent
_PKG_PARENT = _HERE.parent / "sentinel_brief"  # contains the `sentinel_brief` package
if str(_PKG_PARENT) not in sys.path:
    sys.path.insert(0, str(_PKG_PARENT))

from sentinel_brief.mock_service import (  # noqa: E402
    SEED_AUTH_EVENTS,
    SEED_BENIGN_FANOUT_AUTH,
    SEED_EDR_EVENTS,
)

# ---- Column contracts (Splunk CDM-ish, CSV-ingest friendly) ----
AUTH_FIELDS = [
    "_time", "index", "host", "user", "action", "logon_type",
    "src", "dest", "share", "status", "event_id", "scenario",
]
EDR_FIELDS = [
    "_time", "index", "host", "user", "process", "parent_process",
    "cmdline", "signal", "severity", "action", "scenario",
]

# ---- Benign background noise (NOT part of the malicious chain) ----
# Normal nightly admin-share activity by OTHER service accounts on <=3 dests each,
# so the current over-firing rule (dc(dest) > 3 by user) does NOT trip on them.
# These exist only to make the live index realistic. They do not alter the demo.
_BENIGN_AUTH = [
    {"_time": "2026-05-31T01:02:10Z", "host": "WKS-201", "user": "alice",
     "action": "logon", "logon_type": "2", "src": "WKS-201", "dest": "WKS-201",
     "share": "", "status": "success", "event_id": "4624"},
    {"_time": "2026-05-31T01:05:44Z", "host": "WKS-202", "user": "bob",
     "action": "logon", "logon_type": "2", "src": "WKS-202", "dest": "WKS-202",
     "share": "", "status": "success", "event_id": "4624"},
    {"_time": "2026-05-31T02:40:00Z", "host": "WKS-014", "user": "jdoe",
     "action": "logon", "logon_type": "2", "src": "WKS-014", "dest": "WKS-014",
     "share": "", "status": "success", "event_id": "4624"},
]

# EDR baseline for the benign-fanout service accounts. They run real admin tools
# (robocopy / wsusscan / nessus probe) but emit NO attack-tool signal — that empty
# `signal` IS the ground-truth discriminator the new rule keys on.
_BENIGN_EDR = [
    {"_time": "2026-05-31T01:00:05Z", "host": "WKS-201", "user": "alice",
     "process": "chrome.exe", "parent_process": "explorer.exe",
     "cmdline": "chrome.exe --profile-directory=Default",
     "signal": "", "severity": "info", "action": "allowed"},
    {"_time": "2026-05-31T00:21:40Z", "host": "PATCH-01", "user": "svc_patch",
     "process": "wuauclt.exe", "parent_process": "svchost.exe",
     "cmdline": "wuauclt.exe /detectnow /updatenow",
     "signal": "", "severity": "info", "action": "allowed"},
    {"_time": "2026-05-31T00:46:00Z", "host": "SCAN-02", "user": "svc_vuln",
     "process": "nessusd.exe", "parent_process": "services.exe",
     "cmdline": "nessusd.exe --scan creds=svc_vuln",
     "signal": "", "severity": "info", "action": "allowed"},
    {"_time": "2026-05-31T01:33:20Z", "host": "MON-03", "user": "svc_monitor",
     "process": "robocopy.exe", "parent_process": "backup_agent.exe",
     "cmdline": "robocopy \\\\FS-01\\C$\\logs D:\\archive /MIR",
     "signal": "", "severity": "info", "action": "allowed"},
]


def _auth_row(e: dict, scenario: str, *, status: str = "success",
              event_id: str = "4624") -> dict:
    return {
        "_time": e["_time"],
        "index": "auth",
        "host": e.get("host", ""),
        "user": e.get("user", ""),
        "action": e.get("action", ""),
        "logon_type": e.get("logon_type", ""),
        "src": e.get("src", ""),
        "dest": e.get("dest", ""),
        "share": e.get("share", ""),
        "status": e.get("status", status),
        "event_id": e.get("event_id", event_id),
        "scenario": scenario,
    }


def _edr_row(e: dict, scenario: str) -> dict:
    # parent_process: powershell launched by explorer (user action); PsExec by the
    # operator shell. These are implied, not invented chain members.
    parent = e.get("parent_process")
    if parent is None:
        proc = e.get("process", "")
        parent = "explorer.exe" if proc.lower() == "powershell.exe" else "cmd.exe"
    return {
        "_time": e["_time"],
        "index": "edr",
        "host": e.get("host", ""),
        "user": e.get("user", ""),
        "process": e.get("process", ""),
        "parent_process": parent,
        "cmdline": e.get("cmdline", ""),
        "signal": e.get("signal", ""),
        "severity": e.get("severity", "high"),
        "action": e.get("action", "detected"),
        "scenario": scenario,
    }


def build_auth_rows() -> list[dict]:
    rows = [_auth_row(e, "lateral-movement") for e in SEED_AUTH_EVENTS]
    # benign-fanout: legit service accounts that TRIP the old rule (the FP class)
    rows += [_auth_row(e, "benign-fanout") for e in SEED_BENIGN_FANOUT_AUTH]
    rows += [_auth_row(e, "benign-noise") for e in _BENIGN_AUTH]
    rows.sort(key=lambda r: r["_time"])
    return rows


def build_edr_rows() -> list[dict]:
    rows = [_edr_row(e, "lateral-movement") for e in SEED_EDR_EVENTS]
    rows += [_edr_row(e, "benign-noise") for e in _BENIGN_EDR]
    rows.sort(key=lambda r: r["_time"])
    return rows


def _write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> int:
    auth_rows = build_auth_rows()
    edr_rows = build_edr_rows()
    _write_csv(_HERE / "auth.csv", AUTH_FIELDS, auth_rows)
    _write_csv(_HERE / "edr.csv", EDR_FIELDS, edr_rows)

    n_auth_mal = sum(1 for r in auth_rows if r["scenario"] == "lateral-movement")
    n_edr_mal = sum(1 for r in edr_rows if r["scenario"] == "lateral-movement")
    print(f"auth.csv : {len(auth_rows)} rows "
          f"({n_auth_mal} lateral-movement, {len(auth_rows) - n_auth_mal} benign)")
    print(f"edr.csv  : {len(edr_rows)} rows "
          f"({n_edr_mal} lateral-movement, {len(edr_rows) - n_edr_mal} benign)")
    print("Derived from SEED_AUTH_EVENTS / SEED_EDR_EVENTS — no scenario drift.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
