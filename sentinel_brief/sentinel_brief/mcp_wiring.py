"""B6 — wire the remote Splunk MCP Server tools into the agent spine.

The Correlator subagent is the natural home for remote MCP tools: it gathers the
multi-index timeline + blast radius via SPL, so giving it the MCP Server's
`splunk_run_query` / discovery tools means it genuinely queries Splunk THROUGH
the MCP Server (the "Best Use of Splunk MCP Server" bonus). MCP is ADDITIVE — the
local-SPL path (build_live_detection_context / spl_tools) is untouched.

Design constraints honored:
  * LIVE-ONLY: remote MCP is only attempted when SENTINEL_BACKEND=live. Mock mode
    NEVER touches MCP (offline tests stay green, no Splunk/Vertex burn).
  * FAIL-SAFE: connect_remote_mcp can RAISE (non-404 token error, TLS/connect
    failure) — that would otherwise blow up Agent.__aenter__ and break the whole
    demo. We probe MCP up front; if the probe fails we degrade to remote=None so
    the Correlator runs on its local-SPL reasoning path (R5 / R-fallback). The
    brief shape, topology, schema, model tiers and demo path are all unchanged.
  * NO VENDORING: the SDK normally derives app_id via locate_app() which requires
    running inside $SPLUNK_HOME/etc/apps/<app>. We run from sentinel_brief/, so we
    set the SDK's documented testing override (_testing_app_id) to the known app
    id "Splunk_MCP_Server" and point _testing_local_tools_path at a non-existent
    path. Result: local tools are skipped, remote tools get the correct app_id for
    token minting. (local=False means the local branch never runs anyway.)
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from splunklib.ai import agent as _agent_mod
from splunklib.ai.agent import _get_splunk_username  # type: ignore[attr-defined]
from splunklib.ai.tool_settings import (
    RemoteToolSettings,
    ToolAllowlist,
    ToolSettings,
)
from splunklib.ai.tools import connect_remote_mcp

# The MCP Server App id on the live instance (confirmed installed + enabled).
MCP_APP_ID = "Splunk_MCP_Server"

# Allowlisted remote MCP tools exposed to the Correlator. splunk_run_query runs
# arbitrary SPL through the MCP Server (the load-bearing one); the two discovery
# tools let the agent enumerate indexes/metadata via MCP. Names verified against
# /services/mcp_tools this session. saia_* tools are deliberately excluded.
REMOTE_ALLOWLIST_NAMES: tuple[str, ...] = (
    "splunk_run_query",
    "splunk_get_indexes",
    "splunk_get_metadata",
)

_NO_REMOTE = ToolSettings(local=False, remote=None)


def _remote_settings() -> ToolSettings:
    return ToolSettings(
        local=False,
        remote=RemoteToolSettings(
            allowlist=ToolAllowlist(names=list(REMOTE_ALLOWLIST_NAMES))
        ),
    )


def install_app_id_override() -> None:
    """Make the SDK use the known MCP app id without being vendored in an app dir.

    locate_app() raises unless the running script lives under
    $SPLUNK_HOME/etc/apps/<app-id>. We bypass it via the SDK's documented testing
    hooks: a fixed app_id + a non-existent local tools path (so local tools are
    skipped, app_id resolves for remote token minting). Idempotent.
    """
    _agent_mod._testing_app_id = MCP_APP_ID  # type: ignore[attr-defined]
    if _agent_mod._testing_local_tools_path is None:  # type: ignore[attr-defined]
        _agent_mod._testing_local_tools_path = os.path.join(  # type: ignore[attr-defined]
            os.path.dirname(__file__), "_no_local_tools.py"
        )


def _is_live() -> bool:
    return os.environ.get("SENTINEL_BACKEND", "live").strip().lower() == "live"


async def probe_remote_mcp_async(service: Any, *, logger: logging.Logger) -> bool:
    """Best-effort up-front probe: can we mint a token + open the MCP session?

    Async so it runs inside the agent's existing event loop. Returns True only if
    a remote MCP session is established (token minted, app reachable). Any failure
    (exception or None session) -> False, and the caller degrades to the local-SPL
    path. This protects Agent.__aenter__ from the raise that connect_remote_mcp can
    throw at runtime.
    """
    try:
        username = await asyncio.to_thread(lambda: _get_splunk_username(service))
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP probe: could not resolve splunk username (%s); "
                       "degrading to local SPL", exc)
        return False
    try:
        async with connect_remote_mcp(service, MCP_APP_ID, "b6-probe", username) as s:
            if s is None:
                logger.warning("MCP probe: no MCP token minted (app missing or "
                               "user lacks mcp_tool_* caps); degrading to local SPL")
                return False
            logger.info("MCP probe OK: remote MCP session established as user=%s", username)
            return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("MCP probe failed (%s: %s); degrading to local SPL",
                       type(exc).__name__, exc)
        return False


async def resolve_correlator_tool_settings(
    service: Any | None,
    *,
    logger: logging.Logger,
) -> ToolSettings:
    """Async resolver used by the agent spine (inside the running loop).

    * mock mode (SENTINEL_BACKEND!=live): always remote=None (never touch MCP).
    * live mode + no service: remote=None (fail-safe).
    * live mode: probe first; only enable remote MCP tools if the probe succeeds.
    """
    if not _is_live() or service is None:
        return _NO_REMOTE

    if await probe_remote_mcp_async(service, logger=logger):
        install_app_id_override()
        logger.info("Correlator wired with remote MCP tools: %s",
                    list(REMOTE_ALLOWLIST_NAMES))
        return _remote_settings()

    return _NO_REMOTE


def correlator_tool_settings(
    service: Any | None = None,
    *,
    logger: logging.Logger | None = None,
    force_remote: bool = False,
) -> ToolSettings:
    """Sync entry used by tests / the standalone probe to assert the config SHAPE.

    * force_remote=True: return the remote settings without a live call.
    * mock mode or no service: remote=None.
    NOTE: the live agent path uses `resolve_correlator_tool_settings` (async) so
    the MCP probe runs inside the agent's event loop. This sync variant never
    performs the network probe (so it is safe to call anywhere).
    """
    logger = logger or logging.getLogger("sentinel_brief.mcp")

    if force_remote:
        install_app_id_override()
        return _remote_settings()

    if not _is_live() or service is None:
        return _NO_REMOTE

    # No network probe in the sync path — the async resolver handles live probing.
    return _NO_REMOTE


class RemoteToolsEvidenceFilter(logging.Filter):
    """Captures the SDK's `Loaded remote_tools=[...]` debug line + MCP traces as
    evidence the agent discovered/invoked MCP Server tools. Records matching lines
    onto `.captured` for MCP-EVIDENCE.md. Never drops records (filter returns True).
    """

    def __init__(self) -> None:
        super().__init__()
        self.captured: list[str] = []

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        msg = record.getMessage()
        if ("remote_tools=" in msg
                or "MCP Server available" in msg
                or "Probing MCP Server App" in msg
                or "splunk_run_query" in msg
                or "splunk_get_indexes" in msg
                or "splunk_get_metadata" in msg
                or ("requested_tool_calls=" in msg and "requested_tool_calls=[]" not in msg)
                or msg.startswith("tool: ")):
            self.captured.append(msg)
        return True


def make_agent_logger(name: str = "sentinel_brief.correlator") -> tuple[logging.Logger, RemoteToolsEvidenceFilter]:
    """A DEBUG logger wired to capture the remote-tools evidence line. Pass the
    returned logger into the Correlator Agent(logger=...) so the SDK emits
    `Loaded remote_tools=[...]` at DEBUG and we record it.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    ev = RemoteToolsEvidenceFilter()
    logger.addFilter(ev)
    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        h = logging.StreamHandler()
        h.setLevel(logging.DEBUG)
        h.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
        logger.addHandler(h)
    logger.propagate = False
    return logger, ev
