"""Paced API probing of Juice Shop endpoints with response capture."""
from __future__ import annotations

import json
import os
import subprocess
import time

TARGET = "https://juice-shop.herokuapp.com"
BASE = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
import glob
TS = sorted(glob.glob(f"{BASE}/*/"))[-1].split("/")[-2]
EVID = f"{BASE}/{TS}/evidence"


def probe(method, path, data=None, headers=None):
    url = f"{TARGET}{path}"
    cmd = ["curl", "-s", "-m", "30", "-w", "\\n__HTTP_CODE__:%{http_code}", "-X", method, url]
    if data:
        cmd += ["-H", "Content-Type: application/json", "-d", data]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        out = p.stdout
        code = "000"
        if "__HTTP_CODE__:" in out:
            code = out.rsplit("__HTTP_CODE__:", 1)[1].strip()
            out = out.split("__HTTP_CODE__:")[0]
        return {"code": code, "body": out[:3000]}
    except Exception as exc:  # noqa: BLE001
        return {"code": "ERR", "error": str(exc)}


def main():
    os.makedirs(EVID, exist_ok=True)
    results = {}
    probes = [
        ("GET", "/api/products"),
        ("GET", "/api/products/1"),
        ("GET", "/rest/products/search?q=apple"),
        ("GET", "/rest/products/search?q='"),
        ("GET", "/rest/user/whoami"),
        ("GET", "/rest/basket/1"),
        ("GET", "/rest/admin"),
        ("GET", "/rest/chat"),
        ("GET", "/api/feedbacks"),
        ("GET", "/api/users"),
        ("GET", "/api/reviews"),
        ("GET", "/api/orders"),
        ("GET", "/rest/memories"),
        ("GET", "/rest/geo"),
        ("GET", "/rest/order"),
        ("GET", "/rest/captcha"),
        ("GET", "/ftp"),
        ("GET", "/redirect?to=https://example.com"),
        ("GET", "/profile"),
        ("GET", "/administration"),
        ("POST", "/rest/user/login", '{"email":"admin@juice-shop.op","password":"x"}'),
    ]
    for method, path, *rest in probes:
        data = rest[0] if rest else None
        r = probe(method, path, data)
        results[f"{method} {path}"] = r
        print(f"  {method:5} {path:35} -> {r['code']}  {(r.get('body') or '')[:100].replace(chr(10),' ')}")
        time.sleep(1.5)
    json.dump(results, open(f"{EVID}/api-paced-probe.json", "w"), indent=2)
    print("saved api-paced-probe.json")


if __name__ == "__main__":
    main()
