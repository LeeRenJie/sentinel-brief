"""Sentinel Brief — web backend.

Two endpoints:
  GET  /api/brief  -> the cached sample_brief.json. Instant, offline, always works.
                      This is the demo default; the UI bundles the same JSON and
                      never depends on this server being up.
  POST /api/run    -> OPTIONAL. Runs the real run_sentinel_brief pipeline against
                      the configured Splunk backend (live, slow). Gated behind
                      SENTINEL_ALLOW_LIVE=1 so it can't be hit by accident on
                      camera. On any failure it falls back to the cached brief.

Also serves the built frontend (web/dist) statically when present, so the whole
demo can run from a single `uvicorn` process.

Run:
  pip install fastapi uvicorn
  uvicorn backend.app:app --reload --port 8000     # from sentinel_brief/web/
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

WEB_DIR = Path(__file__).resolve().parent.parent          # .../sentinel_brief/web
SAMPLE_BRIEF = WEB_DIR / "sample_brief.json"
DIST_DIR = WEB_DIR / "dist"
DETECTION_NAME = "Excessive Admin-Share Logons by Single Account"

app = FastAPI(title="Sentinel Brief", version="1.0.0")


def _load_cached() -> dict:
    """The canonical cached brief. The demo never fails because of this path."""
    return json.loads(SAMPLE_BRIEF.read_text(encoding="utf-8"))


@app.get("/api/brief")
def get_brief() -> JSONResponse:
    """Cached IncidentBrief. Default demo data source."""
    return JSONResponse(_load_cached())


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "live_enabled": os.getenv("SENTINEL_ALLOW_LIVE") == "1"}


@app.post("/api/run")
async def run_live() -> JSONResponse:
    """Optionally run the real multi-agent pipeline.

    Disabled unless SENTINEL_ALLOW_LIVE=1. Any error (missing deps, no Splunk,
    model timeout) degrades gracefully to the cached brief so the UI never breaks.
    """
    if os.getenv("SENTINEL_ALLOW_LIVE") != "1":
        # Explicitly opted out: hand back the cached brief, flagged as cached.
        return JSONResponse({**_load_cached(), "_source": "cached"})

    try:
        # Import lazily so the server starts even without the heavy splunklib deps.
        import sys

        pkg_root = WEB_DIR.parent  # .../sentinel_brief (the Python package root)
        if str(pkg_root) not in sys.path:
            sys.path.insert(0, str(pkg_root))

        from sentinel_brief.agents import run_sentinel_brief
        from sentinel_brief.backtest import run_backtest
        from sentinel_brief.live_context import build_live_detection_context
        from sentinel_brief.mcp_wiring import RemoteToolsEvidenceFilter
        from sentinel_brief.mock_service import MockService
        from sentinel_brief.service_factory import make_service

        service = make_service()
        is_live = not isinstance(service, MockService)

        if is_live:
            context = build_live_detection_context(service, DETECTION_NAME)
        else:
            # Reuse demo's fired-detection composer for the mock path.
            from demo import _fired_detection_context  # type: ignore

            context = _fired_detection_context()

        mcp_evidence = RemoteToolsEvidenceFilter()
        brief = await run_sentinel_brief(service, context, mcp_evidence=mcp_evidence)
        if not brief.detection_name:
            brief.detection_name = DETECTION_NAME

        if is_live:
            import logging

            bt_logger = logging.getLogger("sentinel_brief.backtest")
            bt_logger.setLevel(logging.INFO)
            bt_logger.addFilter(mcp_evidence)
            brief.detection_backtest = run_backtest(service, logger=bt_logger)

        payload = brief.model_dump()
        payload["_source"] = "live" if is_live else "mock"
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001 — never let the demo break
        return JSONResponse(
            {**_load_cached(), "_source": "cached_fallback", "_error": str(exc)}
        )


# Serve the built SPA last, so /api/* always wins. Mounted only if dist exists.
if DIST_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(DIST_DIR), html=True), name="static")
