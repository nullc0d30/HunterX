# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regenerate the full toolchain intelligence manifest (Sprint 031).

Run:  python -m pytest -q tests/engineering/test_regenerate_toolchain_manifest.py
"""

from __future__ import annotations

import json
import os

from hunterx.tools.mastery.toolchain_manifest import export_manifest

_APPROVED = {
    "amass", "subfinder", "assetfinder", "findomain", "dnsx", "massdns",
    "shuffledns", "naabu", "nmap", "masscan", "rustscan", "httpx", "whatweb",
    "katana", "gospider", "hakrawler", "gau", "waybackurls", "urlfinder",
    "ffuf", "feroxbuster", "gobuster", "dirsearch", "arjun", "paramspider",
    "kiterunner", "linkfinder", "secretfinder", "xnlinkfinder", "nuclei",
    "dalfox", "xssstrike", "sqlmap", "ghauri", "commix", "interactsh",
    "tplmap", "sstimap", "xxeinjector", "graphqlmap", "inql", "gitleaks",
    "trufflehog", "semgrep", "zap", "mitmproxy", "metasploit", "searchsploit",
    "exploitdb", "payloadsallthethings", "seclists", "fuzzdb",
}


def test_regenerate_toolchain_manifest() -> None:
    path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "capabilities",
        "full-toolchain-intelligence.json",
    )
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    export_manifest(path)

    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert manifest["capability"] == "full-toolchain-intelligence"
    assert manifest["manifest_version"] == "1.0.0"
    assert manifest["wave"] == 16
    assert manifest["tool_count"] >= 50
    assert _APPROVED.issubset(set(manifest["tools"])), _APPROVED - set(manifest["tools"])
    assert len(manifest["events"]) == 12
    assert len(manifest["interfaces"]["cli"]) >= 11
    assert len(manifest["interfaces"]["api"]) >= 15
    assert any(source["tool_id"] == "seclists" for source in manifest["knowledge_sources"])
    assert "subdomain-discovery" in manifest["toolchains"]
    assert manifest["toolchains"]["subdomain-discovery"]["primary"]
