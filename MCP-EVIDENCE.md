# Splunk MCP Server — bonus evidence ("Best Use of Splunk MCP Server")

Sentinel Brief's **Correlator** subagent queries Splunk **through the Splunk MCP
Server**: it auto-discovers the remote MCP tools, filters them by an allowlist,
and actually invokes `splunk_run_query` to verify the incident against the live
indexes. This was captured during a live run against a real Splunk Enterprise
instance + Vertex/Gemini spine on 2026-06-07.

## 1. The app is installed and enabled

- `Splunk_MCP_Server` **v1.2.0** installed and enabled on the live Splunk
  Enterprise **10.4.0** instance (mgmt `https://localhost:8089`, self-signed cert).
- Tools exposed by the app (confirmed via `/services/mcp_tools`, 10 total):
  `splunk_run_query`, `splunk_get_indexes`, `splunk_get_index_info`,
  `splunk_get_metadata`, `splunk_get_info`, `splunk_get_user_info`,
  `splunk_get_user_list`, `splunk_get_kv_store_collections`,
  `splunk_get_knowledge_objects`, `splunk_run_saved_search`.

## 2. The MCP token is minted automatically (no manual token)

`splunklib.ai` handles auth end-to-end. On agent start the SDK
(`splunklib/ai/tools.py:connect_remote_mcp`) builds
`https://localhost:8089/services/mcp`, calls the app's token endpoint via the
authenticated `Service` to mint the RSA-encrypted MCP token, and connects with
`Authorization: Bearer <token>` + `x-splunk-app-id`. The connecting user (`RJ`,
an admin holding `mcp_tool_admin` + `mcp_tool_execute`) can mint the token, so:

- **No manual token**, no `.env` MCP token, no `mcp.conf` change required.
- Confirmed log line: `MCP probe OK: remote MCP session established as user=rj`.

## 3. The agent discovers + allowlists the MCP tools

The Correlator is constructed with:

```python
ToolSettings(
    local=False,
    remote=RemoteToolSettings(
        allowlist=ToolAllowlist(names=[
            "splunk_run_query", "splunk_get_indexes", "splunk_get_metadata",
        ])
    ),
)
```

Wiring lives in `sentinel_brief/sentinel_brief/mcp_wiring.py`; it is attached to
the Correlator in `agents.py`. The SDK auto-discovers all 10 remote tools, then
the allowlist filters to the 3 we expose. Captured SDK debug line:

```
Probing MCP Server App availability
Loading remote tools - MCP Server available
Loaded remote_tools=['splunk_get_indexes', 'splunk_run_query', 'splunk_get_metadata']
```

## 4. The agent actually INVOKES an MCP tool (the decisive evidence)

During the live brief run the Correlator called `splunk_run_query` **four times**
through the MCP Server — verifying the admin-share fan-out and the EDR
attack-tool signals against the live `auth`/`edr` indexes before answering:

```
LLM model invocation ended; requested_tool_calls=[('splunk_run_query', '7c756519-…'), ('splunk_run_query', '9ca5e75c-…')]; requested_subagent_calls=[]
Tool call splunk_run_query started; id=7c756519-3eaf-45f4-8802-b95709a08bf8
Tool call splunk_run_query started; id=9ca5e75c-9a06-405b-8a63-26a8653b7de9
Tool call splunk_run_query succeeded; id=9ca5e75c-9a06-405b-8a63-26a8653b7de9
Tool call splunk_run_query succeeded; id=7c756519-3eaf-45f4-8802-b95709a08bf8
LLM model invocation ended; requested_tool_calls=[('splunk_run_query', '07a03053-…'), ('splunk_run_query', 'd5b186ad-…')]; requested_subagent_calls=[]
Tool call splunk_run_query started; id=07a03053-8965-4f2a-b7c3-1aebd8f272ea
Tool call splunk_run_query started; id=d5b186ad-580c-42a6-9a28-cf4bb5d5850b
Tool call splunk_run_query succeeded; id=d5b186ad-580c-42a6-9a28-cf4bb5d5850b
Tool call splunk_run_query succeeded; id=07a03053-8965-4f2a-b7c3-1aebd8f272ea
```

The same run produced a **complete** IncidentBrief: TRUE POSITIVE / HIGH / 100%,
3 MITRE techniques (T1078, T1021.002, T1569.002), a 9-event multi-index timeline,
an 8-entity ranked blast radius, 2 human-approved dry-run containment actions, and
the detection-fix WOW (a unified-diff SPL rule that adds the EDR correlation to
remove the service-account false-positive class while keeping the WKS-014 TP).

## 5. How it's wired (live-gated + fail-safe)

- **Live-only:** remote MCP is attempted only when `SENTINEL_BACKEND=live`. Mock
  mode never touches MCP (offline tests stay green; no Vertex/MCP burn).
- **Fail-safe:** `connect_remote_mcp` can raise (token/connect failure). The
  spine runs an async probe up front (`resolve_correlator_tool_settings`); if it
  fails, the Correlator's `tool_settings.remote` is set to `None` and it falls
  back to its local-SPL reasoning path (R-fallback). The brief shape, agent
  topology, schema, model tiers, and demo output are unchanged either way.
- **No app vendoring required:** the SDK normally derives the app id via
  `locate_app()` (which needs the script to live under `$SPLUNK_HOME/etc/apps/`).
  We run from `sentinel_brief/`, so we set the SDK's documented testing override
  (`_testing_app_id = "Splunk_MCP_Server"`) to supply the app id for token
  minting without being vendored into the app.

## 6. Reproduce

```bash
# Discovery only (no Vertex burn):
SENTINEL_BACKEND=live sentinel_brief/.venv/Scripts/python sentinel_brief/probe_mcp.py

# Full live brief with MCP tool-call trace:
GOOGLE_CLOUD_PROJECT=<proj> GOOGLE_CLOUD_LOCATION=us-central1 \
  SENTINEL_BACKEND=live sentinel_brief/.venv/Scripts/python sentinel_brief/demo.py
```

Credentials are read from `sentinel_brief/.env` (never passed on a command line).
The demo prints the captured `[mcp]` evidence block after the brief.
