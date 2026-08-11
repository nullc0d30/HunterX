# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonical tool relationship data for the Sprint 025 arsenal.

Encodes how arsenal tools relate: which enables another, which validates
another, which must precede/follow, which specializes another. The graph
powers chaining, alternatives, conflict detection and "what should I run
next" reasoning.
"""

from __future__ import annotations

from hunterx.domain.tool_mastery import ToolRelationship, ToolRelationshipKind

#: Canonical relationship edges for the arsenal.
RELATIONSHIPS: tuple[ToolRelationship, ...] = (
    # -- recon / subdomain -> probing -> crawling ---------------------------
    ToolRelationship("subfinder", "httpx", ToolRelationshipKind.ENABLES, "http-probing", "Subdomains need live probing to be useful."),
    ToolRelationship("subfinder", "httpx", ToolRelationshipKind.FOLLOWS, "http-probing", "Run httpx after subfinder."),
    ToolRelationship("httpx", "subfinder", ToolRelationshipKind.PRECEDES, "http-probing", "Subfinder runs before httpx."),
    ToolRelationship("amass", "httpx", ToolRelationshipKind.ENABLES, "http-probing", "Amass results feed probing."),
    ToolRelationship("assetfinder", "httpx", ToolRelationshipKind.FOLLOWS, "http-probing", "Assetfinder output needs live probing."),
    ToolRelationship("findomain", "httpx", ToolRelationshipKind.FOLLOWS, "http-probing", "Findomain output needs live probing."),
    ToolRelationship("bbot", "httpx", ToolRelationshipKind.ENABLES, "http-probing", "BBOT discovered hosts should be probed."),
    ToolRelationship("crt-sh", "httpx", ToolRelationshipKind.FOLLOWS, "http-probing", "CT-derived names need probing."),
    ToolRelationship("dnsx", "httpx", ToolRelationshipKind.ENABLES, "http-probing", "Resolved hosts are probed with httpx."),
    ToolRelationship("httpx", "katana", ToolRelationshipKind.ENABLES, "crawling", "Live hosts are crawled next."),
    ToolRelationship("httpx", "nuclei", ToolRelationshipKind.ENABLES, "web-vulnerability-detection", "Probed surface is scanned by nuclei."),
    ToolRelationship("httpx", "nuclei", ToolRelationshipKind.FOLLOWS, "web-vulnerability-detection", "Nuclei runs after probing."),
    ToolRelationship("httpx", "nuclei", ToolRelationshipKind.PRECEDES, "web-vulnerability-detection", "Probing precedes nuclei scanning."),
    # -- crawling -> parameters -> injection testing ------------------------
    ToolRelationship("katana", "arjun", ToolRelationshipKind.ENABLES, "parameter-discovery", "Crawled endpoints feed parameter discovery."),
    ToolRelationship("gospider", "arjun", ToolRelationshipKind.ENABLES, "parameter-discovery", "Spider output feeds parameter discovery."),
    ToolRelationship("katana", "linkfinder", ToolRelationshipKind.ENABLES, "endpoint-extraction", "Crawl results feed JS analysis."),
    ToolRelationship("katana", "jsluice", ToolRelationshipKind.ENABLES, "javascript-analysis", "Crawl results feed JS analysis."),
    ToolRelationship("linkfinder", "secretfinder", ToolRelationshipKind.ENABLES, "secret-indicator-discovery", "Endpoints found in JS feed secret scanning."),
    ToolRelationship("linkfinder", "secretfinder", ToolRelationshipKind.FOLLOWS, "secret-indicator-discovery", "SecretFinder runs after LinkFinder."),
    ToolRelationship("arjun", "sqlmap", ToolRelationshipKind.ENABLES, "sql-injection-detection", "Hidden parameters are injection candidates."),
    ToolRelationship("arjun", "dalfox", ToolRelationshipKind.ENABLES, "xss-discovery", "Hidden parameters are XSS candidates."),
    ToolRelationship("arjun", "nuclei", ToolRelationshipKind.ENABLES, "web-vulnerability-detection", "Hidden parameters expand scan surface."),
    # -- port scanning -> service detection -> vuln scanning ----------------
    ToolRelationship("naabu", "nmap", ToolRelationshipKind.ENABLES, "service-discovery", "Open ports feed service detection."),
    ToolRelationship("naabu", "nmap", ToolRelationshipKind.FOLLOWS, "service-discovery", "Nmap validates naabu open ports."),
    ToolRelationship("masscan", "nmap", ToolRelationshipKind.ENABLES, "service-discovery", "Masscan results need Nmap service detection."),
    ToolRelationship("rustscan", "nmap", ToolRelationshipKind.ENABLES, "service-discovery", "RustScan pipes into Nmap."),
    ToolRelationship("nmap", "nuclei", ToolRelationshipKind.ENABLES, "web-vulnerability-detection", "Detected services feed nuclei templates."),
    ToolRelationship("nmap", "nuclei", ToolRelationshipKind.FOLLOWS, "web-vulnerability-detection", "Nuclei runs after service detection."),
    ToolRelationship("nmap", "searchsploit", ToolRelationshipKind.ENABLES, "exploit-research", "Versions feed exploit research."),
    ToolRelationship("nmap", "searchsploit", ToolRelationshipKind.FOLLOWS, "exploit-research", "Search exploits after version detection."),
    ToolRelationship("dnsx", "massdns", ToolRelationshipKind.SPECIALIZES, "dns-resolution", "dnsx is higher-level than massdns."),
    ToolRelationship("dnspython", "dnsx", ToolRelationshipKind.REPLACES, "dns-resolution", "dnspython is an in-process alternative."),
    # -- vulnerability scanning -> validation --------------------------------
    ToolRelationship("nuclei", "dalfox", ToolRelationshipKind.ENABLES, "xss-validation", "Nuclei XSS candidates feed Dalfox validation."),
    ToolRelationship("nuclei", "sqlmap", ToolRelationshipKind.ENABLES, "sql-injection-validation", "Nuclei SQLi candidates feed sqlmap validation."),
    ToolRelationship("nuclei", "interactsh", ToolRelationshipKind.ENABLES, "oob-callback", "Blind findings need OOB correlation."),
    ToolRelationship("nuclei", "searchsploit", ToolRelationshipKind.FOLLOWS, "exploit-research", "Research public exploits after template match."),
    ToolRelationship("zap", "nuclei", ToolRelationshipKind.ENABLES, "web-vulnerability-detection", "ZAP observation feeds targeted scans."),
    ToolRelationship("zap", "dalfox", ToolRelationshipKind.ENABLES, "xss-validation", "ZAP findings feed validation."),
    ToolRelationship("zap", "mitmproxy", ToolRelationshipKind.REPLACES, "http-interception", "Both intercept; choose by workflow."),
    ToolRelationship("wapiti", "sqlmap", ToolRelationshipKind.ENABLES, "sql-injection-validation", "Wapiti candidates feed sqlmap."),
    ToolRelationship("wapiti", "dalfox", ToolRelationshipKind.ENABLES, "xss-validation", "Wapiti candidates feed Dalfox."),
    # -- injection validation -> proof ---------------------------------------
    ToolRelationship("sqlmap", "proof-replay", ToolRelationshipKind.ENABLES, "impact-statement", "Validated SQLi feeds proof replay."),
    ToolRelationship("dalfox", "proof-replay", ToolRelationshipKind.ENABLES, "impact-statement", "Validated XSS feeds proof replay."),
    ToolRelationship("interactsh", "proof-replay", ToolRelationshipKind.ENABLES, "impact-statement", "Correlated OOB evidence feeds proof."),
    ToolRelationship("sqlmap", "ghauri", ToolRelationshipKind.REPLACES, "sql-injection-validation", "Ghauri is an alternative to sqlmap."),
    ToolRelationship("dalfox", "xssstrike", ToolRelationshipKind.REPLACES, "xss-validation", "XSStrike is an alternative to Dalfox."),
    ToolRelationship("sstimap", "tplmap", ToolRelationshipKind.REPLACES, "ssti-validation", "SSTImap is the maintained alternative."),
    ToolRelationship("commix", "interactsh", ToolRelationshipKind.ENABLES, "oob-callback", "Command injection validation uses OOB callbacks."),
    # -- secrets ---------------------------------------------------------------
    ToolRelationship("gitleaks", "trufflehog", ToolRelationshipKind.REPLACES, "secret-discovery", "TruffleHog covers git history."),
    ToolRelationship("gitleaks", "detect-secrets", ToolRelationshipKind.REPLACES, "secret-discovery", "detect-secrets is a CI-friendly alternative."),
    ToolRelationship("secretfinder", "trufflehog", ToolRelationshipKind.ENABLES, "credential-discovery", "JS secrets feed credential verification."),
    ToolRelationship("secretfinder", "trufflehog", ToolRelationshipKind.FOLLOWS, "credential-discovery", "Verify discovered JS secrets."),
    # -- cloud / container ------------------------------------------------------
    ToolRelationship("prowler", "scoutsuite", ToolRelationshipKind.REPLACES, "cloud-misconfiguration", "Both audit cloud posture."),
    ToolRelationship("prowler", "nuclei", ToolRelationshipKind.ENABLES, "cloud-exposure-detection", "Cloud findings feed exposure checks."),
    ToolRelationship("syft", "trivy", ToolRelationshipKind.ENABLES, "cve-analysis", "SBOMs feed Trivy scans."),
    ToolRelationship("syft", "grype", ToolRelationshipKind.ENABLES, "cve-analysis", "SBOMs feed Grype scans."),
    ToolRelationship("syft", "grype", ToolRelationshipKind.FOLLOWS, "cve-analysis", "Grype consumes Syft SBOMs."),
    ToolRelationship("osv-scanner", "grype", ToolRelationshipKind.REPLACES, "dependency-analysis", "OSV-scanner maps to OSV advisories."),
    # -- enterprise / AD ----------------------------------------------------------
    ToolRelationship("netexec", "impacket", ToolRelationshipKind.ENABLES, "smb-enumeration", "NetExec uses Impacket protocol clients."),
    ToolRelationship("netexec", "ldapsearch", ToolRelationshipKind.ENABLES, "active-directory-intelligence", "Enumerated hosts feed LDAP queries."),
    ToolRelationship("netexec", "enum4linux-ng", ToolRelationshipKind.REPLACES, "smb-enumeration", "Both enumerate SMB surfaces."),
    ToolRelationship("impacket", "rpcclient", ToolRelationshipKind.REPLACES, "smb-enumeration", "Both provide SMB/RPC clients."),
    ToolRelationship("enum4linux-ng", "rpcclient", ToolRelationshipKind.ENABLES, "windows-enumeration", "rpcclient deepens enum4linux-ng results."),
    # -- payload / wordlists --------------------------------------------------------
    ToolRelationship("cewl", "ffuf", ToolRelationshipKind.ENABLES, "content-discovery", "Custom wordlists feed ffuf."),
    ToolRelationship("cewl", "ffuf", ToolRelationshipKind.FOLLOWS, "content-discovery", "Use generated wordlists in fuzzing."),
    ToolRelationship("cewl", "gobuster", ToolRelationshipKind.ENABLES, "directory-enumeration", "Custom wordlists feed gobuster."),
    # -- exploit intelligence --------------------------------------------------------
    ToolRelationship("searchsploit", "metasploit", ToolRelationshipKind.ENABLES, "exploit-validation", "Researched exploits feed validation."),
    ToolRelationship("searchsploit", "metasploit", ToolRelationshipKind.FOLLOWS, "exploit-validation", "Validate researched exploits."),
    ToolRelationship("searchsploit", "exploitdb", ToolRelationshipKind.REPLACES, "exploit-research", "ExploitDB is the online reference."),
    # -- SAST --------------------------------------------------------------------------
    ToolRelationship("semgrep", "codeql", ToolRelationshipKind.REPLACES, "sast", "Semgrep is a lighter SAST alternative."),
    # -- knowledge / payload / wordlist sources (Sprint 031) ----------------------------
    ToolRelationship("payloadsallthethings", "dalfox", ToolRelationshipKind.ENABLES, "xss-validation", "Payload library feeds XSS hypothesis generation."),
    ToolRelationship("payloadsallthethings", "sqlmap", ToolRelationshipKind.ENABLES, "sql-injection-validation", "Payload library feeds SQLi hypotheses."),
    ToolRelationship("payloadsallthethings", "commix", ToolRelationshipKind.ENABLES, "command-injection-validation", "Payload library feeds command injection hypotheses."),
    ToolRelationship("seclists", "ffuf", ToolRelationshipKind.ENABLES, "content-discovery", "SecLists wordlists feed ffuf."),
    ToolRelationship("seclists", "ffuf", ToolRelationshipKind.FOLLOWS, "content-discovery", "Use SecLists wordlists in fuzzing."),
    ToolRelationship("seclists", "gobuster", ToolRelationshipKind.ENABLES, "directory-enumeration", "SecLists wordlists feed gobuster."),
    ToolRelationship("fuzzdb", "ffuf", ToolRelationshipKind.ENABLES, "web-fuzzing", "FuzzDB attack patterns feed fuzzing."),
    ToolRelationship("fuzzdb", "dalfox", ToolRelationshipKind.ENABLES, "xss-validation", "FuzzDB payloads feed XSS validation."),
    ToolRelationship("fuzzdb", "sqlmap", ToolRelationshipKind.ENABLES, "sql-injection-validation", "FuzzDB payloads feed SQLi validation."),
)


def register_default_relationships(graph) -> None:
    """Register every canonical relationship into a graph.

    Args:
        graph: a :class:`ToolRelationshipGraph` instance.

    """
    graph.add_many(list(RELATIONSHIPS))
