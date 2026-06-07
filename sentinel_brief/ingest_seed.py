"""A1-A3 ingest: create auth/edr indexes and load the seed CSVs into live Splunk,
PRESERVING the real 2026-05-31 event timestamps (not ingest-time).

Credentials are read from .env via sentinel_brief.splunk_env (NEVER on the command
line). Idempotent: skips index creation if the index already exists; events are
re-submitted each run (use a fresh index or clean first if you re-run).

Strategy for timestamp preservation:
  Each event is submitted as a single line that BEGINS with the ISO-8601 _time
  value. Splunk's default datetime parser extracts the leading timestamp, so the
  event lands at 2026-05-31, regardless of ingest time. The remaining fields are
  appended as key=value pairs (auto-extracted at search time), and we also send a
  `time=<epoch>` param on the receivers/simple POST as an explicit hint.

Run:
  .venv/Scripts/python.exe ingest_seed.py
"""
from __future__ import annotations

import csv
import sys
import time as _time_mod
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from sentinel_brief.splunk_env import (
    insecure_ssl_context,
    live_service,
    splunk_settings,
)

# seed_data/ lives at the workspace root, one level above the sentinel_brief/ project dir
SEED_DIR = Path(__file__).resolve().parent.parent / "seed_data"
FILES = {"auth": SEED_DIR / "auth.csv", "edr": SEED_DIR / "edr.csv"}


def _epoch(iso: str) -> float:
    dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _event_line(row: dict[str, str]) -> tuple[str, float]:
    """Build a kv-line that begins with the timestamp; return (line, epoch)."""
    t = row["_time"]
    epoch = _epoch(t)
    # leading timestamp so Splunk's default time parser picks it up,
    # followed by the remaining fields as key=value (skip _time/index dupes).
    parts = [t]
    for k, v in row.items():
        if k in ("_time", "index"):
            continue
        v = "" if v is None else str(v)
        if " " in v or '"' in v:
            v = '"' + v.replace('"', '\\"') + '"'
        parts.append(f"{k}={v}")
    return " ".join(parts), epoch


def ensure_indexes(service) -> dict[str, str]:
    out = {}
    existing = {i.name for i in service.indexes}
    for name in FILES:
        if name in existing:
            out[name] = "exists"
        else:
            service.indexes.create(name)
            out[name] = "created"
    return out


def _post_event(host: str, port: int, user: str, pw: str, index: str,
                line: str, epoch: float, sourcetype: str,
                event_host: str) -> None:
    """POST one event to receivers/simple. event_host sets the metadata host so
    the indexed `host` field matches the scenario row (e.g. WKS-014), instead of
    the receiver overriding it with a generic seed host."""
    params = {
        "index": index,
        "sourcetype": sourcetype,
        "source": f"seed:{index}",
        "host": event_host or "sentinel-seed",
    }
    url = (
        f"https://{host}:{port}/services/receivers/simple?"
        + urllib.parse.urlencode(params)
    )
    pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwmgr.add_password(None, url, user, pw)
    opener = urllib.request.build_opener(
        urllib.request.HTTPBasicAuthHandler(pwmgr),
        urllib.request.HTTPSHandler(context=insecure_ssl_context()),
    )
    req = urllib.request.Request(url, data=line.encode("utf-8"), method="POST")
    with opener.open(req, timeout=20) as resp:
        resp.read()


def ingest(service) -> dict[str, int]:
    cfg = splunk_settings()
    counts = {}
    for index, path in FILES.items():
        sourcetype = f"seed_{index}"
        n = 0
        with path.open(newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                line, epoch = _event_line(row)
                _post_event(
                    cfg["host"], cfg["port"], cfg["username"], cfg["password"],
                    index, line, epoch, sourcetype,
                    event_host=row.get("host", ""),
                )
                n += 1
        counts[index] = n
    return counts


def clean_indexes(service) -> None:
    """Remove all events from the seed indexes (idempotent re-ingest)."""
    existing = {i.name: i for i in service.indexes}
    for name in FILES:
        if name in existing:
            existing[name].clean(timeout=120)


def main() -> int:
    do_clean = "--clean" in sys.argv
    service = live_service()
    print("[ingest] connected:", service.info.get("serverName"), service.info.get("version"))

    created = ensure_indexes(service)
    print("[ingest] indexes:", created)

    if do_clean:
        clean_indexes(service)
        print("[ingest] indexes cleaned (events purged before re-ingest).")

    counts = ingest(service)
    print("[ingest] submitted events:", counts)
    print("[ingest] events are async-indexed; allow a few seconds before verify.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
