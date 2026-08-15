"""Endpoint + API discovery against Juice Shop."""
from __future__ import annotations

import json
import os
import subprocess

os.environ.pop("HUNTERX_DATABASE_URL", None)
os.environ.pop("HUNTERX_DB_URL", None)

TARGET = "https://juice-shop.herokuapp.com"
BASE = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
import glob
TS = sorted(glob.glob(f"{BASE}/*/"))[-1].split("/")[-2]
EVID = f"{BASE}/{TS}/evidence"


def run(cmd, label, timeout=300):
    rec = {"label": label, "command": list(cmd)}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rec["exit"] = p.returncode
        rec["stdout"] = p.stdout[:8000]
        rec["stderr"] = p.stderr[:2000]
    except subprocess.TimeoutExpired:
        rec["exit"] = 124
        rec["stdout"] = "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        rec["exit"] = -1
        rec["error"] = str(exc)
    json.dump(rec, open(f"{EVID}/{label}.json", "w"), indent=2)
    print(f"[{rec['exit']}] {label}")
    return rec


def main():
    os.makedirs(EVID, exist_ok=True)
    # Katana crawl
    run(["katana", "-u", TARGET, "-d", "3", "-jc", "-kf", "all", "-silent", "-o", f"{EVID}/katana-urls.txt"], "katana-crawl", 400)
    # GAU historical URLs
    run(["gau", "--threads", "5", "juice-shop.herokuapp.com", "-o", f"{EVID}/gau-urls.txt"], "gau-urls", 400)
    # WayBackUrls
    run(["waybackurls", "juice-shop.herokuapp.com", "-o", f"{EVID}/wayback-urls.txt"], "wayback-urls", 400)
    # Common Juice Shop API endpoints
    endpoints = [
        "/rest/products/search?q=",
        "/api/products",
        "/api/products/1",
        "/rest/user/login",
        "/rest/user/register",
        "/rest/user/whoami",
        "/rest/basket/1",
        "/rest/admin",
        "/rest/chat",
        "/rest/order",
        "/rest/simple-quiz",
        "/api/feedbacks",
        "/api/users",
        "/api/basket-items",
        "/api/reviews",
        "/api/orders",
        "/api/Deliverys",
        "/rest/captcha/",
        "/rest/geo/",
        "/rest/memories/",
        "/ftp",
        "/profile",
        "/administration",
        "/track-order",
    ]
    probe = {}
    for ep in endpoints:
        url = f"{TARGET}{ep}"
        try:
            p = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}", url], capture_output=True, text=True, timeout=30)
            code, size = p.stdout.split("|")
            probe[ep] = {"code": code, "size": int(size)}
        except Exception as exc:  # noqa: BLE001
            probe[ep] = {"error": str(exc)}
    json.dump(probe, open(f"{EVID}/api-probe.json", "w"), indent=2)
    print("api-probe:", json.dumps(probe, indent=1))


if __name__ == "__main__":
    main()
