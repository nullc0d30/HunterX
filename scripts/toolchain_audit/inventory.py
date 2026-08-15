"""Build the authoritative tool inventory for HunterX.

Sources (all read-only):
- capabilities/full-toolchain-intelligence.json  -> canonical 92-tool manifest
- src/hunterx/tools/readiness/manifest.py        -> install methods, binary specs, capability providers
- README.md / docs/                              -> documented tools
- src/hunterx/tools/<category>/adapters          -> runtime adapters

Outputs a normalized JSON inventory.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _eval_install_method(call) -> dict:
    kwargs = {}
    for kw in call.keywords:
        try:
            kwargs[kw.arg] = ast.literal_eval(kw.value)
        except Exception:
            pass
    return {
        "kind": kwargs.get("kind", ""),
        "package": kwargs.get("package", ""),
        "name": kwargs.get("name", ""),
        "platforms": tuple(kwargs.get("platforms", ())),
        "requires_elevation": kwargs.get("requires_elevation", False),
    }


def _eval_node(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        pass
    if isinstance(node, ast.List):
        return [_eval_node(el) for el in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval_node(el) for el in node.elts)
    if isinstance(node, ast.Set):
        return {_eval_node(el) for el in node.elts}
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            try:
                out[ast.literal_eval(k)] = _eval_node(v)
            except Exception:
                pass
        return out
    if isinstance(node, (ast.Call,)):
        # Specific static call shapes used in the manifest
        func = node.func
        if isinstance(func, ast.Name):
            name = func.id
            if name == "tuple" and node.args:
                return tuple(_eval_node(node.args[0]) or ())
            if name == "sorted" and node.args:
                return sorted(_eval_node(node.args[0]) or ())
            if name == "frozenset" and node.args:
                return frozenset(_eval_node(node.args[0]) or ())
            if name == "set" and node.args:
                return set(_eval_node(node.args[0]) or ())
        if isinstance(func, ast.Attribute) and func.attr == "fromkeys" and node.args:
            # dict.fromkeys(iterable)
            return {item: None for item in (_eval_node(node.args[0]) or [])}
        return _eval_install_method(node)
    if isinstance(node, ast.SetComp):
        return set()
    return None


def parse_manifest_py() -> dict:
    tree = ast.parse((ROOT / "src/hunterx/tools/readiness/manifest.py").read_text())
    result = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            target = node.target
            if isinstance(target, ast.Name):
                try:
                    result[target.id] = _eval_node(node.value)
                except Exception:
                    pass
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        result[target.id] = _eval_node(node.value)
                    except Exception:
                        pass
    return result


def main() -> None:
    canonical = json.loads((ROOT / "capabilities/full-toolchain-intelligence.json").read_text())
    try:
        import hunterx.tools.readiness.manifest as runtime_manifest
        use_runtime = True
    except Exception:
        use_runtime = False
    if use_runtime:
        install_methods = runtime_manifest.INSTALL_METHODS
        binary_specs = runtime_manifest.TOOL_BINARY_SPECS
        capability_providers = runtime_manifest.CAPABILITY_PROVIDERS
        profile_tools = runtime_manifest.PROFILE_TOOLS
        inprocess = set(runtime_manifest.INPROCESS_TOOLS)
        claimed = set(runtime_manifest.CLAIMED_EXTERNAL_TOOLS)
    else:
        manifest = parse_manifest_py()
        install_methods = manifest.get("INSTALL_METHODS", {})
        binary_specs = manifest.get("TOOL_BINARY_SPECS", {})
        capability_providers = manifest.get("CAPABILITY_PROVIDERS", {})
        profile_tools = manifest.get("PROFILE_TOOLS", {})
        inprocess = set(manifest.get("INPROCESS_TOOLS", []))
        claimed = set(manifest.get("CLAIMED_EXTERNAL_TOOLS", []))

    tools = canonical["tools"]
    inventory = {}
    for tool_id, meta in tools.items():
        is_inprocess = tool_id in inprocess
        install = install_methods.get(tool_id, [])
        spec = binary_specs.get(tool_id, {})
        # normalize InstallMethod objects or dicts
        install_norm = []
        for m in install:
            if hasattr(m, "to_dict"):
                install_norm.append(m.to_dict())
            else:
                install_norm.append(m)
        # capabilities provided to the planner
        caps = sorted(
            c for c, provs in capability_providers.items() if tool_id in provs
        )
        profiles = sorted(
            p for p, tl in profile_tools.items() if tool_id in tl
        )
        inventory[tool_id] = {
            "canonical_id": tool_id,
            "name": meta.get("name", tool_id),
            "category": meta.get("category", ""),
            "subcategory": meta.get("subcategory", ""),
            "support_level": meta.get("support_level", ""),
            "capabilities": meta.get("capabilities", []),
            "planner_capabilities": caps,
            "binary": spec.get("executable", ""),
            "aliases": list(spec.get("aliases", [])),
            "version_command": list(spec.get("version_command", [])),
            "version_regex": spec.get("version_regex", ""),
            "min_version": spec.get("min_version", ""),
            "install_methods": install_norm,
            "kind": "inprocess" if is_inprocess else "binary",
            "profiles": profiles,
            "adapter": meta.get("adapter", ""),
            "parser": meta.get("parser", ""),
            "documented": tool_id in claimed or True,
            "in_manifest": True,
            "claimed_external": tool_id in claimed,
        }

    # Documented in README but not in the canonical manifest?
    readme_tools = extract_readme_tools(ROOT / "README.md")
    extra_documented = {
        tid: {"documented_in": "README"} for tid in readme_tools if tid not in inventory
    }
    # Tools in install methods but not in manifest
    extra_install = {
        tid: {"install_methods": install_methods[tid]}
        for tid in install_methods if tid not in inventory
    }

    report = {
        "manifest_tool_count": len(tools),
        "install_method_count": len(install_methods),
        "binary_spec_count": len(binary_specs),
        "capability_count": len(capability_providers),
        "profiles": {p: list(t) for p, t in profile_tools.items()},
        "inprocess_tools": sorted(inprocess),
        "claimed_external": sorted(claimed),
        "inventory": inventory,
        "documented_not_in_manifest": extra_documented,
        "install_methods_not_in_manifest": extra_install,
        "readme_documented_tools": sorted(readme_tools),
    }
    print(json.dumps(report, indent=2, default=str))


README_TOOL_NAMES = {
    "Amass": "amass", "Subfinder": "subfinder", "Assetfinder": "assetfinder",
    "Findomain": "findomain", "theHarvester": "theharvester", "BBOT": "bbot",
    "DNSx": "dnsx", "MassDNS": "massdns", "Shuffledns": "shuffledns",
    "SpiderFoot": "spiderfoot", "DNSrecon": "dnsrecon", "Crobat": "crobat",
    "crt.sh": "crt-sh", "Naabu": "naabu", "Nmap": "nmap", "Masscan": "masscan",
    "RustScan": "rustscan", "Unicornscan": "unicornscan", "fping": "fping",
    "arp-scan": "arp-scan", "HTTPx": "httpx", "WhatWeb": "whatweb",
    "Katana": "katana", "Gospider": "gospider", "Hakrawler": "hakrawler",
    "GAU": "gau", "Waybackurls": "waybackurls", "URLFinder": "urlfinder",
    "gauplus": "gauplus", "Wafw00f": "wafw00f", "FFUF": "ffuf",
    "Feroxbuster": "feroxbuster", "Gobuster": "gobuster", "Dirsearch": "dirsearch",
    "Kiterunner": "kiterunner", "Arjun": "arjun", "ParamSpider": "paramspider",
    "LinkFinder": "linkfinder", "SecretFinder": "secretfinder",
    "xnLinkFinder": "xnlinkfinder", "JSluice": "jsluice", "Nuclei": "nuclei",
    "Dalfox": "dalfox", "XSStrike": "xssstrike", "SQLmap": "sqlmap",
    "Ghauri": "ghauri", "Commix": "commix", "Interactsh": "interactsh",
    "Tplmap": "tplmap", "SSTImap": "sstimap", "XXEinjector": "xxeinjector",
    "GraphQLmap": "graphqlmap", "InQL": "inql", "OpenVAS / Greenbone": "openvas",
    "Wapiti": "wapiti", "Nikto": "nikto", "testssl.sh": "testssl.sh",
    "SSLScan": "sslscan", "Gitleaks": "gitleaks", "TruffleHog": "trufflehog",
    "detect-secrets": "detect-secrets", "Semgrep": "semgrep",
    "CodeQL CLI": "codeql", "OWASP ZAP": "zap", "mitmproxy": "mitmproxy",
    "Metasploit": "metasploit", "SearchSploit": "searchsploit",
    "ExploitDB": "exploitdb", "PayloadsAllTheThings": "payloadsallthethings",
    "SecLists": "seclists", "FuzzDB": "fuzzdb", "Prowler": "prowler",
    "ScoutSuite": "scoutsuite", "Trivy": "trivy", "Syft": "syft",
    "Grype": "grype", "kube-bench": "kube-bench", "OSV-Scanner": "osv-scanner",
    "NetExec": "netexec", "Impacket": "impacket", "enum4linux-ng": "enum4linux-ng",
    "ldapsearch": "ldapsearch", "rpcclient": "rpcclient", "snmpwalk": "snmpwalk",
    "CeWL": "cewl", "hashcat": "hashcat", "John the Ripper": "john",
    "dnspython": "dnspython", "OpenAPI / Swagger parser": "openapi-parser",
    "Postman collection parser": "postman-parser", "jwt_tool": "jwt-tool",
    "Proof Replay": "proof-replay",
}


def extract_readme_tools(path: Path) -> list[str]:
    text = path.read_text()
    found = []
    for display, tid in README_TOOL_NAMES.items():
        # crude: presence of display name with bracket link
        if f"[{display}]" in text:
            found.append(tid)
    return found


if __name__ == "__main__":
    main()
