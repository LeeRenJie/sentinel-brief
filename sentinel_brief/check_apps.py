"""List installed Splunk apps (looks for the MCP Server App). Reads creds from
.env — no secret on the command line."""
from __future__ import annotations

import json
import ssl
import urllib.request
from pathlib import Path

from check_conn import load_env  # reuse loader


def main() -> int:
    env = load_env(Path(__file__).with_name(".env"))
    host, port = env.get("SPLUNK_HOST", "localhost"), env.get("SPLUNK_PORT", "8089")
    user, pw = env.get("SPLUNK_USERNAME", "admin"), env.get("SPLUNK_PASSWORD", "")
    url = f"https://{host}:{port}/services/apps/local?output_mode=json&count=0"

    pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwmgr.add_password(None, url, user, pw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPBasicAuthHandler(pwmgr),
        urllib.request.HTTPSHandler(context=ctx),
    )
    with opener.open(url, timeout=15) as resp:
        data = json.load(resp)

    apps = [e["name"] for e in data.get("entry", [])]
    mcp = [a for a in apps if "mcp" in a.lower() or "model_context" in a.lower()]
    print(f"total apps: {len(apps)}")
    print(f"MCP-related apps: {mcp if mcp else 'NONE FOUND'}")
    # also surface anything that looks AI/agent related
    ai = [a for a in apps if any(k in a.lower() for k in ("ai", "assist", "agent"))]
    print(f"AI/assistant-related apps: {ai if ai else 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
