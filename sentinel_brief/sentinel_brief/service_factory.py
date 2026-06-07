"""B5 — backend selector. Returns the Splunk Service the agent spine consumes.

  SENTINEL_BACKEND=live  (default) -> real splunklib.client.connect via .env
  SENTINEL_BACKEND=mock            -> MockService (offline tests, no-Splunk demo)

Both expose the identical surface the agents/tools use (.jobs.oneshot, .get), so
NOTHING in agents.py / schemas.py / render.py / the demo path changes — only the
data source. R-fallback: if live connect fails and SENTINEL_BACKEND is unset
(i.e. caller didn't force live), fall back to mock so a no-Splunk box still runs.
"""
from __future__ import annotations

import os
from typing import Any

from .mock_service import MockService


def make_service(backend: str | None = None) -> Any:
    """Build the Service for the chosen backend.

    backend: 'live' | 'mock'. If None, read SENTINEL_BACKEND (default 'live').
    """
    choice = (backend or os.environ.get("SENTINEL_BACKEND", "live")).strip().lower()

    if choice == "mock":
        return MockService()

    if choice == "live":
        from .splunk_env import live_service

        forced = os.environ.get("SENTINEL_BACKEND", "").strip().lower() == "live"
        try:
            return live_service()
        except Exception as exc:  # noqa: BLE001
            if forced:
                # caller explicitly demanded live — surface the failure
                raise
            # R-fallback: no Splunk reachable and live wasn't forced -> mock
            print(f"[service] live Splunk unavailable ({type(exc).__name__}: {exc}); "
                  "falling back to MockService (set SENTINEL_BACKEND=live to fail hard).")
            return MockService()

    raise ValueError(f"Unknown SENTINEL_BACKEND={choice!r} (use 'live' or 'mock').")
