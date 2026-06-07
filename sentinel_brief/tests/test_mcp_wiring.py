"""B6 offline tests — lock the remote MCP tool-settings SHAPE without touching
Splunk or Vertex. These assert the config the agent ships, the live/mock gate,
and the evidence filter. No network, no model, no MCP connect.
"""
from __future__ import annotations

import logging

from splunklib.ai.tool_settings import RemoteToolSettings, ToolSettings

from sentinel_brief.mcp_wiring import (
    MCP_APP_ID,
    REMOTE_ALLOWLIST_NAMES,
    RemoteToolsEvidenceFilter,
    correlator_tool_settings,
)


def test_force_remote_shape_is_valid_and_allowlisted():
    ts = correlator_tool_settings(force_remote=True)
    assert isinstance(ts, ToolSettings)
    assert ts.local is False  # we never load local tools via this path
    assert isinstance(ts.remote, RemoteToolSettings)
    names = list(ts.remote.allowlist.names)
    assert names == list(REMOTE_ALLOWLIST_NAMES)
    assert "splunk_run_query" in names  # the load-bearing arbitrary-SPL MCP tool


def test_mock_backend_never_enables_remote(monkeypatch):
    monkeypatch.setenv("SENTINEL_BACKEND", "mock")
    ts = correlator_tool_settings(service=object())
    assert ts.remote is None  # mock mode must NOT attempt MCP


def test_live_backend_without_service_is_safe(monkeypatch):
    monkeypatch.setenv("SENTINEL_BACKEND", "live")
    # No service handed in -> cannot probe -> degrade to remote=None (fail-safe).
    ts = correlator_tool_settings(service=None)
    assert ts.remote is None


def test_app_id_is_the_installed_app():
    assert MCP_APP_ID == "Splunk_MCP_Server"


def test_evidence_filter_captures_remote_tools_line():
    ev = RemoteToolsEvidenceFilter()
    rec = logging.LogRecord(
        "x", logging.DEBUG, __file__, 1,
        "Loaded remote_tools=['splunk_run_query', 'splunk_get_indexes']", None, None,
    )
    assert ev.filter(rec) is True  # never drops the record
    assert ev.captured and "remote_tools=" in ev.captured[0]


def test_evidence_filter_ignores_unrelated_lines():
    ev = RemoteToolsEvidenceFilter()
    rec = logging.LogRecord("x", logging.DEBUG, __file__, 1, "unrelated", None, None)
    assert ev.filter(rec) is True
    assert ev.captured == []
