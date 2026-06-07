"""B6 probe — confirm remote MCP tool discovery against live Splunk WITHOUT
burning Vertex. Connects via the SDK's connect_remote_mcp using the same Service
the agent uses, mints the MCP token automatically, lists the remote tools, and
applies the allowlist. No model is constructed. Creds read from .env only.
"""
from __future__ import annotations

import asyncio
import logging

from sentinel_brief.service_factory import make_service
from sentinel_brief.mcp_wiring import (
    REMOTE_ALLOWLIST_NAMES,
    correlator_tool_settings,
)
from splunklib.ai.agent import _get_splunk_username
from splunklib.ai.tools import ToolType, connect_remote_mcp, load_mcp_tools

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("probe_mcp")


async def main() -> int:
    service = make_service("live")
    username = _get_splunk_username(service)
    log.info("connected as splunk user=%s; mgmt=%s://%s:%s",
             username, service.scheme, service.host, service.port)

    app_id = "Splunk_MCP_Server"
    trace_id = "b6-probe"
    async with connect_remote_mcp(service, app_id, trace_id, username) as session:
        if session is None:
            log.error("connect_remote_mcp returned None (no MCP token / app missing)")
            return 2
        tools = await load_mcp_tools(session, ToolType.REMOTE, app_id, trace_id, service)
        names = [t.name for t in tools]
        log.info("Discovered remote MCP tools (%d): %s", len(names), names)
        allowed = [n for n in names if n in REMOTE_ALLOWLIST_NAMES]
        log.info("Allowlisted (will be exposed to Correlator): %s", allowed)
        # sanity: confirm the tool_settings shape we ship is valid
        ts = correlator_tool_settings(force_remote=True)
        log.info("Correlator tool_settings.remote allowlist names=%s",
                 list(ts.remote.allowlist.names))
        return 0 if allowed else 3


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
