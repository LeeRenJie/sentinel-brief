"""Restart splunkd via REST and wait until the mgmt API is back. Creds from .env."""
from __future__ import annotations

import ssl
import time
import urllib.request
from pathlib import Path

from check_conn import load_env


def _opener(user: str, pw: str, url: str):
    pwmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwmgr.add_password(None, url, user, pw)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.HTTPBasicAuthHandler(pwmgr),
        urllib.request.HTTPSHandler(context=ctx),
    )


def main() -> int:
    env = load_env(Path(__file__).with_name(".env"))
    host, port = env.get("SPLUNK_HOST", "localhost"), env.get("SPLUNK_PORT", "8089")
    user, pw = env.get("SPLUNK_USERNAME", "admin"), env.get("SPLUNK_PASSWORD", "")
    base = f"https://{host}:{port}"

    restart_url = f"{base}/services/server/control/restart"
    info_url = f"{base}/services/server/info?output_mode=json"

    print("requesting restart ...")
    try:
        _opener(user, pw, restart_url).open(
            urllib.request.Request(restart_url, data=b""), timeout=30
        )
    except Exception as e:  # noqa: BLE001 — splunkd often drops the connection mid-restart
        print(f"  (restart request returned: {type(e).__name__} — expected as splunkd goes down)")

    print("waiting for splunkd to come back (up to ~180s) ...")
    deadline = 180
    waited = 0
    step = 5
    while waited < deadline:
        time.sleep(step)
        waited += step
        try:
            _opener(user, pw, info_url).open(info_url, timeout=8)
            print(f"  UP after ~{waited}s")
            return 0
        except Exception:  # noqa: BLE001
            print(f"  ... still restarting ({waited}s)")
    print("TIMEOUT: splunkd did not come back within the window")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
