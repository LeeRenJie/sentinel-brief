"""Diagnostics for the MCP Server app: app state, restart-required messages,
mcp_* capabilities, and the current user's roles/capabilities. Creds from .env."""
from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request
from pathlib import Path

from check_conn import load_env

ENV = load_env(Path(__file__).with_name(".env"))
HOST, PORT = ENV.get("SPLUNK_HOST", "localhost"), ENV.get("SPLUNK_PORT", "8089")
USER, PW = ENV.get("SPLUNK_USERNAME", "admin"), ENV.get("SPLUNK_PASSWORD", "")
BASE = f"https://{HOST}:{PORT}"


def get(path: str):
    url = f"{BASE}{path}"
    sep = "&" if "?" in url else "?"
    url = f"{url}{sep}output_mode=json&count=0"
    pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwmgr.add_password(None, url, USER, PW)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPBasicAuthHandler(pwmgr),
        urllib.request.HTTPSHandler(context=ctx),
    )
    with opener.open(url, timeout=20) as resp:
        return json.load(resp)


def main() -> int:
    # 1. App state
    app = get("/services/apps/local/Splunk_MCP_Server")["entry"][0]
    c = app["content"]
    print("APP Splunk_MCP_Server:")
    print(f"  version       : {c.get('version')}")
    print(f"  disabled      : {c.get('disabled')}")
    print(f"  state_change_requires_restart : {c.get('state_change_requires_restart')}")
    print(f"  configured    : {c.get('configured')}")

    # 2. Restart-required messages
    try:
        msgs = get("/services/messages").get("entry", [])
        restart_msgs = [m["name"] for m in msgs if "restart" in (m["name"] + json.dumps(m.get("content", {}))).lower()]
        print(f"\nrestart-required messages: {restart_msgs if restart_msgs else 'none'}")
    except Exception as e:  # noqa: BLE001
        print(f"\n(messages check failed: {e})")

    # 3. mcp_* capabilities present?
    caps = [e["name"] for e in get("/services/authorization/capabilities").get("entry", [])]
    mcp_caps = [x for x in caps if "mcp" in x.lower()]
    print(f"\nmcp_* capabilities registered: {mcp_caps if mcp_caps else 'NONE (restart may not have taken)'}")

    # 4. Current user roles + whether they already have mcp_tool_execute
    me = get(f"/services/authentication/users/{urllib.parse.quote(USER)}")["entry"][0]["content"]
    roles = me.get("roles", [])
    print(f"\nuser '{USER}' roles: {roles}")
    for r in roles:
        try:
            rc = get(f"/services/authorization/roles/{urllib.parse.quote(r)}")["entry"][0]["content"]
            rcaps = rc.get("capabilities", []) + rc.get("imported_capabilities", [])
            has = [x for x in rcaps if "mcp" in x.lower()]
            print(f"  role {r}: mcp caps = {has if has else 'none'}")
        except Exception as e:  # noqa: BLE001
            print(f"  role {r}: (lookup failed: {e})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
