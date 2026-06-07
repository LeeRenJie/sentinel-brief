"""Connectivity check: reads .env, hits Splunk mgmt API, prints server info.

Password is read from .env (never passed on the command line). Uses only the
stdlib so it runs on any Python.
"""
from __future__ import annotations

import json
import ssl
import urllib.request
from pathlib import Path


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


def main() -> int:
    env = load_env(Path(__file__).with_name(".env"))
    host = env.get("SPLUNK_HOST", "localhost")
    port = env.get("SPLUNK_PORT", "8089")
    user = env.get("SPLUNK_USERNAME", "admin")
    pw = env.get("SPLUNK_PASSWORD", "")

    if not pw or pw == "changeme":
        print("FAIL: SPLUNK_PASSWORD not set in .env")
        return 2

    url = f"https://{host}:{port}/services/server/info?output_mode=json"
    pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwmgr.add_password(None, url, user, pw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPBasicAuthHandler(pwmgr),
        urllib.request.HTTPSHandler(context=ctx),
    )
    try:
        with opener.open(url, timeout=15) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        print(f"FAIL: HTTP {e.code} {e.reason} — check username/password in .env")
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: {type(e).__name__}: {e}")
        return 1

    c = data["entry"][0]["content"]
    print("CONNECTED OK")
    print(f"  host       : {host}:{port}")
    print(f"  serverName : {c.get('serverName')}")
    print(f"  version    : {c.get('version')}")
    print(f"  os         : {c.get('os_name')} {c.get('cpu_arch')}")
    print(f"  roles      : {', '.join(c.get('server_roles', [])[:6])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
