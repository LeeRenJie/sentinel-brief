"""Shared Splunk connection helpers (B5). Credentials are read from .env —
NEVER passed on a command line. Self-signed cert on the local instance, so TLS
verification is disabled for the management API (10.4.0 dev box).

`load_env` mirrors check_conn.py's proven pattern. `live_service()` returns a
real splunklib.client.Service whose .jobs.oneshot / .get API is identical to the
MockService drop-in, so the agent spine consumes either with no change (B5).
"""
from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Any


def _env_path() -> Path:
    """Locate .env: the sentinel_brief/ project root (one level above this pkg)."""
    override = os.environ.get("SENTINEL_ENV_FILE")
    if override:
        return Path(override)
    # this file: sentinel_brief/sentinel_brief/splunk_env.py -> .env at parent.parent
    return Path(__file__).resolve().parent.parent / ".env"


def load_env(path: Path | None = None) -> dict[str, str]:
    """Parse a KEY=VALUE .env file (same parser as check_conn.py)."""
    p = path or _env_path()
    env: dict[str, str] = {}
    if not p.exists():
        return env
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


def splunk_settings() -> dict[str, Any]:
    """Connection settings from .env (with safe fallbacks). No secrets logged."""
    env = load_env()
    return {
        "host": env.get("SPLUNK_HOST", "localhost"),
        "port": int(env.get("SPLUNK_PORT", "8089")),
        "username": env.get("SPLUNK_USERNAME", "admin"),
        "password": env.get("SPLUNK_PASSWORD", ""),
    }


def insecure_ssl_context() -> ssl.SSLContext:
    """TLS context that accepts the local self-signed cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def live_service():
    """Connect to the live Splunk management API via splunklib using .env creds.

    Returns a splunklib.client.Service. Exposes .jobs.oneshot(spl) and
    .get(path_segment=...) — the same surface MockService implements — so the
    agents/tools consume it unchanged (B5 swap).
    """
    import splunklib.client as client

    cfg = splunk_settings()
    if not cfg["password"] or cfg["password"] == "changeme":
        raise RuntimeError("SPLUNK_PASSWORD not set in .env — cannot connect live.")
    return client.connect(
        host=cfg["host"],
        port=cfg["port"],
        username=cfg["username"],
        password=cfg["password"],
        verify=False,  # self-signed cert on the local 10.4.0 box
    )
