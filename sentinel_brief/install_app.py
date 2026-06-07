"""Install/upgrade a Splunk app from a local package via REST. Creds from .env
(no secret on the command line). Pass the absolute .tgz path as argv[1]."""
from __future__ import annotations

import json
import ssl
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from check_conn import load_env


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: install_app.py <abs-path-to-app.tgz>")
        return 2
    pkg = sys.argv[1]

    env = load_env(Path(__file__).with_name(".env"))
    host, port = env.get("SPLUNK_HOST", "localhost"), env.get("SPLUNK_PORT", "8089")
    user, pw = env.get("SPLUNK_USERNAME", "admin"), env.get("SPLUNK_PASSWORD", "")

    url = f"https://{host}:{port}/services/apps/local"
    body = urllib.parse.urlencode(
        {"name": pkg, "filename": "true", "update": "1", "output_mode": "json"}
    ).encode()

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
        with opener.open(urllib.request.Request(url, data=body), timeout=120) as resp:
            data = json.load(resp)
        name = data.get("entry", [{}])[0].get("name", "?")
        print(f"INSTALL OK: app '{name}' installed/updated from {pkg}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"INSTALL FAILED: HTTP {e.code} {e.reason}")
        print(e.read().decode(errors="replace")[:1500])
        return 1
    except Exception as e:  # noqa: BLE001
        print(f"INSTALL FAILED: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
