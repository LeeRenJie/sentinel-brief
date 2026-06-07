"""Poll splunkd mgmt API until it responds (or timeout). Creds from .env."""
from __future__ import annotations

import ssl
import time
import urllib.request
from pathlib import Path

from check_conn import load_env


def main() -> int:
    env = load_env(Path(__file__).with_name(".env"))
    host, port = env.get("SPLUNK_HOST", "localhost"), env.get("SPLUNK_PORT", "8089")
    user, pw = env.get("SPLUNK_USERNAME", "admin"), env.get("SPLUNK_PASSWORD", "")
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
    waited, deadline, step = 0, 240, 6
    while waited < deadline:
        try:
            opener.open(url, timeout=8)
            print(f"UP after ~{waited}s")
            return 0
        except Exception:  # noqa: BLE001
            time.sleep(step)
            waited += step
            print(f"  ... waiting ({waited}s)")
    print("TIMEOUT")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
