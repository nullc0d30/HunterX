"""Safe smoke tests for every selected executable tool provider.

Each tool is invoked with a harmless probe (--version / --help / safe target).
Proves binary + invocation + runtime + output.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

TOOLS = [
    # recon
    ("subfinder", ["-version"], "subfinder"),
    ("amass", ["-version"], "amass"),
    ("assetfinder", ["-h"], "assetfinder"),
    ("bbot", ["--version"], "bbot"),
    ("theharvester", ["-h"], "theHarvester"),
    ("dnsrecon", ["-h"], "dnsrecon"),
    # dns
    ("dnsx", ["-version"], "dnsx"),
    ("shuffledns", ["-version"], "shuffledns"),
    # port scanning
    ("nmap", ["--version"], "nmap"),
    ("rustscan", ["--version"], "rustscan"),
    ("naabu", ["-version"], "naabu"),
    ("masscan", ["--version"], "masscan"),
    # network
    ("fping", ["-v"], "fping"),
    ("arp-scan", ["--version"], "arp-scan"),
    ("ldapsearch", ["-VV"], "ldapsearch"),
    ("rpcclient", ["-V"], "rpcclient"),
    ("snmpwalk", ["-V"], "snmpwalk"),
    # http / tech
    ("httpx", ["-version"], "httpx"),
    ("whatweb", ["--version"], "whatweb"),
    ("wapiti", ["--version"], "wapiti"),
    ("nikto", ["-Version"], "nikto"),
    ("sslscan", ["--version"], "sslscan"),
    ("testssl.sh", ["--version"], "testssl"),
    # crawling
    ("katana", ["-version"], "katana"),
    ("gospider", ["-version"], "gospider"),
    ("hakrawler", ["-h"], "hakrawler"),
    ("gau", ["--version"], "gau"),
    ("waybackurls", ["-h"], "waybackurls"),
    ("gauplus", ["-h"], "gauplus"),
    # content discovery
    ("ffuf", ["-V"], "ffuf"),
    ("gobuster", ["version"], "gobuster"),
    ("feroxbuster", ["--version"], "feroxbuster"),
    ("dirsearch", ["--version"], "dirsearch"),
    # parameters
    ("arjun", ["-h"], "arjun"),
    ("paramspider", ["-h"], "paramspider"),
    # vuln
    ("nuclei", ["-version"], "nuclei"),
    ("sqlmap", ["--version"], "sqlmap"),
    ("ghauri", ["--version"], "ghauri"),
    ("commix", ["-v"], "commix"),
    ("dalfox", ["--version"], "dalfox"),
    ("xsstrike", ["-h"], "xsstrike"),
    ("tplmap", ["-h"], "tplmap"),
    ("interactsh", ["-version"], "interactsh-client"),
    ("graphqlmap", ["-h"], "graphqlmap"),
    ("inql", ["-h"], "inql"),
    # secrets
    ("gitleaks", ["version"], "gitleaks"),
    ("trufflehog", ["--version"], "trufflehog"),
    ("detect-secrets", ["--version"], "detect-secrets"),
    # sast
    ("semgrep", ["--version"], "semgrep"),
    # proxy
    ("mitmproxy", ["--version"], "mitmproxy"),
    # exploitation
    ("searchsploit", ["--version"], "searchsploit"),
    # cloud
    ("prowler", ["--version"], "prowler"),
    ("scoutsuite", ["--help"], "scout"),
    # composition
    ("osv-scanner", ["--version"], "osv-scanner"),
    # payload
    ("cewl", ["--help"], "cewl"),
    ("hashcat", ["--version"], "hashcat"),
    ("john", [], "john"),
]


def run(tool_id: str, argv: list[str], binary: str) -> dict:
    path = shutil.which(binary)
    if path is None:
        return {"tool": tool_id, "binary": binary, "found": False, "smoke": "NOT_FOUND", "output": ""}
    try:
        completed = subprocess.run(
            [path, *argv], capture_output=True, text=True, timeout=20, check=False
        )
        combined = (completed.stdout or "") + (completed.stderr or "")
        ok = completed.returncode in (0, 1, 2) and len(combined.strip()) > 0
        return {
            "tool": tool_id, "binary": binary, "found": True,
            "path": path, "exit": completed.returncode,
            "smoke": "PASS" if ok else "CHECK",
            "output": combined.strip()[:120],
        }
    except subprocess.TimeoutExpired:
        return {"tool": tool_id, "binary": binary, "found": True, "path": path, "smoke": "TIMEOUT", "output": ""}
    except Exception as exc:  # noqa: BLE001
        return {"tool": tool_id, "binary": binary, "found": True, "path": path, "smoke": f"ERROR: {exc}", "output": ""}


def main() -> None:
    results = [run(tid, argv, binary) for tid, argv, binary in TOOLS]
    json.dump(results, open("/home/nc/hunterx/HunterX/artifacts/toolchain-audit/smoke-tests.json", "w"), indent=2)
    passed = sum(1 for r in results if r["smoke"] == "PASS")
    not_found = [r["tool"] for r in results if r["smoke"] == "NOT_FOUND"]
    checked = [r["tool"] for r in results if r["smoke"] not in ("PASS", "NOT_FOUND")]
    print(f"SMOKE PASS: {passed}/{len(results)}")
    print("NOT_FOUND:", not_found)
    print("CHECK/TIMEOUT/ERROR:", checked)
    for r in results:
        if r["smoke"] != "PASS":
            print(f"  {r['tool']}: {r['smoke']} | {r['output'][:80]}")


if __name__ == "__main__":
    main()
