"""GET the MCP Server app's tool-enablement state via /services/mcp_tools.
Requires mcp_tool_admin (RJ/admin has it). Creds from .env."""
from __future__ import annotations

import json
import ssl
import urllib.request
from pathlib import Path

from check_conn import load_env

ENV = load_env(Path(__file__).with_name(".env"))
HOST, PORT = ENV.get("SPLUNK_HOST", "localhost"), ENV.get("SPLUNK_PORT", "8089")
USER, PW = ENV.get("SPLUNK_USERNAME", "admin"), ENV.get("SPLUNK_PASSWORD", "")


def call(path: str):
    url = f"https://{HOST}:{PORT}{path}"
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
        return resp.read().decode(errors="replace")


def main() -> int:
    for path in ("/services/mcp_tools?output_mode=json",
                 "/servicesNS/nobody/Splunk_MCP_Server/mcp_tools?output_mode=json"):
        try:
            raw = call(path)
            print(f"OK {path}:")
            try:
                print(json.dumps(json.loads(raw), indent=2)[:3000])
            except Exception:
                print(raw[:3000])
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"  {path} -> {type(e).__name__}: {e}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
