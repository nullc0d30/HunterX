"""Deep reconnaissance against Juice Shop with full output capture to evidence/."""
from __future__ import annotations

import json
import os
import subprocess

os.environ.pop("HUNTERX_DATABASE_URL", None)
os.environ.pop("HUNTERX_DB_URL", None)

TARGET = "https://juice-shop.herokuapp.com"
HOST = "juice-shop.herokuapp.com"
EVID = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
import glob
TS = sorted(glob.glob(f"{EVID}/*/"))[-1].split("/")[-2]
EVID_DIR = f"{EVID}/{TS}/evidence"


def run(cmd: list[str], label: str) -> dict:
    rec = {"label": label, "command": cmd}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        rec["exit"] = p.returncode
        rec["stdout"] = p.stdout[:6000]
        rec["stderr"] = p.stderr[:2000]
    except subprocess.TimeoutExpired:
        rec["exit"] = 124
        rec["stdout"] = "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        rec["exit"] = -1
        rec["error"] = str(exc)
    fn = f"{EVID_DIR}/{label}.json"
    json.dump(rec, open(fn, "w"), indent=2)
    print(f"[{rec['exit']}] {label} saved")
    return rec


def main() -> None:
    import os as _os
    _os.makedirs(EVID_DIR, exist_ok=True)

    # 1. HTTP header + robots + sitemap (curl)
    run(["curl", "-sSI", TARGET], "http-headers")
    run(["curl", "-s", f"{TARGET}/robots.txt"], "robots-txt")
    run(["curl", "-s", f"{TARGET}/sitemap.xml"], "sitemap-xml")
    run(["curl", "-s", TARGET], "homepage-html")

    # 2. DNS
    run(["dig", "+short", "A", HOST], "dns-a")
    run(["dig", "+short", "CNAME", HOST], "dns-cname")
    run(["dig", "+short", "MX", HOST], "dns-mx")
    run(["dig", "+short", "TXT", HOST], "dns-txt")

    # 3. nmap top ports
    run(["nmap", "-sT", "--top-ports", "50", HOST, "-oN", f"{EVID_DIR}/nmap.txt"], "nmap-top50")


if __name__ == "__main__":
    main()
