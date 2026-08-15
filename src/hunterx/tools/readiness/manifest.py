# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Trusted static tool readiness manifest.

The authoritative, machine-readable inventory of the EXTERNAL security tools
HunterX integrates. It is the single source of truth for:

- planner capability → provider tool ids (used by the tool selection engine
  and the readiness capability resolver);
- per-tool binary name, version probe command and version regex;
- trusted static installation methods (apt/go/cargo/pip/brew/...). Package
  names and module paths are static constants — user or target input NEVER
  influences an install command;
- installation profiles (minimal/recon/web/network/vulnerability/full).

Tool knowledge (purpose, capabilities, arguments, safety) lives in the TIP
registry; this manifest only adds what discovery/provisioning need so the
planner never hardcodes tool facts.
"""

from __future__ import annotations

from hunterx.tools.readiness.models import CapabilityLevel, InstallMethod
from hunterx.tools.readiness.platform import PlatformInfo

#: Canonical profile names understood by ``hunterx tools install --profile``.
PROFILES: tuple[str, ...] = ("minimal", "recon", "web", "network", "vulnerability", "full")

#: Per-tool install methods. ``go`` methods use the go module path as ``name``;
#: package-manager methods use the package name as ``package``.
INSTALL_METHODS: dict[str, tuple[InstallMethod, ...]] = {
    # -- ProjectDiscovery / go toolchain -------------------------------------
    "subfinder": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        InstallMethod(kind="brew", package="projectdiscovery/tap/subfinder", platforms=("darwin",)),
        InstallMethod(kind="apt", package="subfinder", platforms=("linux",), requires_elevation=True),
    ),
    "bbot": (
        InstallMethod(kind="pip", package="bbot"),
    ),
    "theharvester": (
        InstallMethod(kind="pip", package="theHarvester"),
    ),
    "urlfinder": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"),
    ),
    "spiderfoot": (
        InstallMethod(kind="pip", package="spiderfoot"),
        InstallMethod(kind="apt", package="spiderfoot", platforms=("linux",), requires_elevation=True),
    ),
    "amass": (
        InstallMethod(kind="go", name="github.com/owasp-amass/amass/v4/cmd/amass@master"),
        InstallMethod(kind="brew", package="owasp-amass", platforms=("darwin",)),
        InstallMethod(kind="apt", package="amass", platforms=("linux",), requires_elevation=True),
    ),
    "assetfinder": (
        InstallMethod(kind="go", name="github.com/tomnomnom/assetfinder@latest"),
    ),
    "findomain": (
        InstallMethod(kind="cargo", package="findomain"),
        InstallMethod(kind="brew", package="findomain", platforms=("darwin",)),
    ),
    "dnsx": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        InstallMethod(kind="brew", package="projectdiscovery/tap/dnsx", platforms=("darwin",)),
    ),
    "massdns": (
        InstallMethod(kind="apt", package="massdns", platforms=("linux",), requires_elevation=True),
    ),
    "shuffledns": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    ),
    "httpx": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        InstallMethod(kind="brew", package="projectdiscovery/tap/httpx", platforms=("darwin",)),
    ),
    "katana": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/katana/cmd/katana@latest"),
        InstallMethod(kind="brew", package="projectdiscovery/tap/katana", platforms=("darwin",)),
    ),
    "gospider": (
        InstallMethod(kind="go", name="github.com/jaeles-project/gospider@latest"),
    ),
    "hakrawler": (
        InstallMethod(kind="go", name="github.com/hakluke/hakrawler@latest"),
    ),
    "gau": (
        InstallMethod(kind="go", name="github.com/lc/gau/v2/cmd/gau@latest"),
    ),
    "waybackurls": (
        InstallMethod(kind="go", name="github.com/tomnomnom/waybackurls@latest"),
    ),
    "ffuf": (
        InstallMethod(kind="go", name="github.com/ffuf/ffuf/v2@latest"),
        InstallMethod(kind="brew", package="ffuf", platforms=("darwin",)),
    ),
    "nuclei": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        InstallMethod(kind="brew", package="projectdiscovery/tap/nuclei", platforms=("darwin",)),
    ),
    "dalfox": (
        InstallMethod(kind="go", name="github.com/hahwul/dalfox/v2@latest"),
    ),
    "gitleaks": (
        InstallMethod(kind="go", name="github.com/zricethezav/gitleaks/v8@latest"),
        InstallMethod(kind="brew", package="gitleaks", platforms=("darwin",)),
        InstallMethod(kind="choco", package="gitleaks", platforms=("windows",), requires_elevation=True),
    ),
    "trufflehog": (
        InstallMethod(kind="go", name="github.com/trufflesecurity/trufflehog/v3@latest"),
        InstallMethod(kind="brew", package="trufflehog", platforms=("darwin",)),
    ),
    "interactsh": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    ),
    "naabu": (
        InstallMethod(kind="go", name="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
        InstallMethod(kind="brew", package="projectdiscovery/tap/naabu", platforms=("darwin",)),
    ),
    # -- system / apt ---------------------------------------------------------
    "nmap": (
        InstallMethod(kind="apt", package="nmap", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="nmap", platforms=("darwin",)),
        InstallMethod(kind="choco", package="nmap", platforms=("windows",), requires_elevation=True),
    ),
    "masscan": (
        InstallMethod(kind="apt", package="masscan", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="masscan", platforms=("darwin",)),
        InstallMethod(kind="choco", package="masscan", platforms=("windows",), requires_elevation=True),
    ),
    "rustscan": (
        InstallMethod(kind="cargo", package="rustscan"),
        InstallMethod(kind="apt", package="rustscan", platforms=("linux",), requires_elevation=True),
    ),
    "whatweb": (
        InstallMethod(kind="apt", package="whatweb", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="whatweb", platforms=("darwin",)),
    ),
    "gobuster": (
        InstallMethod(kind="apt", package="gobuster", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="gobuster", platforms=("darwin",)),
        InstallMethod(kind="go", name="github.com/OJ/gobuster/v3@latest"),
        InstallMethod(kind="choco", package="gobuster", platforms=("windows",), requires_elevation=True),
    ),
    "feroxbuster": (
        InstallMethod(kind="cargo", package="feroxbuster"),
        InstallMethod(kind="apt", package="feroxbuster", platforms=("linux",), requires_elevation=True),
    ),
    "metasploit": (
        InstallMethod(kind="apt", package="metasploit-framework", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="metasploit", platforms=("darwin",)),
        InstallMethod(kind="choco", package="metasploit", platforms=("windows",), requires_elevation=True),
    ),
    "searchsploit": (
        InstallMethod(kind="apt", package="exploitdb", platforms=("linux",), requires_elevation=True),
    ),
    "nikto": (
        InstallMethod(kind="apt", package="nikto", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="nikto", platforms=("darwin",)),
    ),
    # -- python / pip ---------------------------------------------------------
    "sqlmap": (
        InstallMethod(kind="pip", package="sqlmap"),
        InstallMethod(kind="apt", package="sqlmap", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="choco", package="sqlmap", platforms=("windows",), requires_elevation=True),
    ),
    "dirsearch": (
        InstallMethod(kind="pip", package="dirsearch"),
        InstallMethod(kind="apt", package="dirsearch", platforms=("linux",), requires_elevation=True),
    ),
    "arjun": (
        InstallMethod(kind="pip", package="arjun"),
        InstallMethod(kind="pipx", package="arjun"),
    ),
    "paramspider": (
        InstallMethod(kind="pip", package="paramspider"),
        InstallMethod(kind="pipx", package="paramspider"),
    ),
    "ghauri": (
        InstallMethod(kind="pip", package="ghauri"),
        InstallMethod(kind="pipx", package="ghauri"),
    ),
    "commix": (
        InstallMethod(kind="pip", package="commix"),
        InstallMethod(kind="pipx", package="commix"),
    ),
    "sstimap": (
        InstallMethod(kind="pip", package="sstimap"),
        InstallMethod(kind="pipx", package="sstimap"),
    ),
    "graphqlmap": (
        InstallMethod(kind="pip", package="graphqlmap"),
        InstallMethod(kind="pipx", package="graphqlmap"),
    ),
    "inql": (
        InstallMethod(kind="pip", package="inql"),
        InstallMethod(kind="pipx", package="inql"),
    ),
    "xssstrike": (
        InstallMethod(kind="pip", package="xssstrike"),
    ),
    "tplmap": (
        InstallMethod(kind="pip", package="tplmap"),
    ),
    "mitmproxy": (
        InstallMethod(kind="pip", package="mitmproxy"),
        InstallMethod(kind="pipx", package="mitmproxy"),
    ),
    "semgrep": (
        InstallMethod(kind="pip", package="semgrep"),
        InstallMethod(kind="pipx", package="semgrep"),
    ),
    "wapiti": (
        InstallMethod(kind="pip", package="wapiti"),
        InstallMethod(kind="apt", package="wapiti", platforms=("linux",), requires_elevation=True),
    ),
    "detect-secrets": (
        InstallMethod(kind="pip", package="detect-secrets"),
    ),
    "dnsrecon": (
        InstallMethod(kind="apt", package="dnsrecon", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="dnsrecon", platforms=("darwin",)),
    ),
    # -- other binary tools ---------------------------------------------------
    "zap": (
        InstallMethod(kind="brew", package="zaproxy", platforms=("darwin",)),
    ),
    "wafw00f": (
        InstallMethod(kind="pip", package="wafw00f"),
        InstallMethod(kind="apt", package="wafw00f", platforms=("linux",), requires_elevation=True),
    ),
    "testssl.sh": (
        InstallMethod(kind="apt", package="testssl.sh", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="testssl.sh", platforms=("darwin",)),
    ),
    "sslscan": (
        InstallMethod(kind="apt", package="sslscan", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="sslscan", platforms=("darwin",)),
    ),
    "openvas": (
        InstallMethod(kind="apt", package="gvm", platforms=("linux",), requires_elevation=True),
    ),
    "osv-scanner": (
        InstallMethod(kind="go", name="github.com/google/osv-scanner/cmd/osv-scanner@latest"),
    ),
    "trivy": (
        InstallMethod(kind="brew", package="aquasecurity/trivy/trivy", platforms=("darwin",)),
    ),
    "prowler": (
        InstallMethod(kind="pip", package="prowler"),
        InstallMethod(kind="pipx", package="prowler"),
    ),
    "scoutsuite": (
        InstallMethod(kind="pip", package="scoutsuite"),
        InstallMethod(kind="pipx", package="scoutsuite"),
    ),
    "hashcat": (
        InstallMethod(kind="apt", package="hashcat", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="hashcat", platforms=("darwin",)),
    ),
    "john": (
        InstallMethod(kind="apt", package="john", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="john", platforms=("darwin",)),
    ),
    "cewl": (
        InstallMethod(kind="apt", package="cewl", platforms=("linux",), requires_elevation=True),
        InstallMethod(kind="brew", package="cewl", platforms=("darwin",)),
    ),
}

#: Binary names / version probes / minimum versions per tool.
#: ``executable`` is the primary binary; ``aliases`` are fallbacks to probe.
#: ``version_command`` is the static argv requesting the version.
#: ``version_regex`` extracts the semver-ish version from stdout (group 1).
TOOL_BINARY_SPECS: dict[str, dict[str, object]] = {
    "subfinder": {"executable": "subfinder", "version_command": ("-version",), "version_regex": r"(?:version)\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "amass": {"executable": "amass", "version_command": ("-version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "assetfinder": {"executable": "assetfinder", "version_command": ("-h",)},
    "findomain": {"executable": "findomain", "version_command": ("-v",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "dnsx": {"executable": "dnsx", "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "massdns": {"executable": "massdns", "version_command": ("-h",)},
    "shuffledns": {"executable": "shuffledns", "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "httpx": {"executable": "httpx", "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "1.6.0"},
    "whatweb": {"executable": "whatweb", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "katana": {"executable": "katana", "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "gospider": {"executable": "gospider", "version_command": ("-version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "hakrawler": {"executable": "hakrawler", "version_command": ("-v",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "gau": {"executable": "gau", "version_command": ("--version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "waybackurls": {"executable": "waybackurls", "version_command": ("-h",)},
    "ffuf": {"executable": "ffuf", "version_command": ("-V",), "version_regex": r"version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "2.0.0"},
    "feroxbuster": {"executable": "feroxbuster", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "2.9.0"},
    "gobuster": {"executable": "gobuster", "version_command": ("version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "3.0.0"},
    "dirsearch": {"executable": "dirsearch", "version_command": ("--version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "arjun": {"executable": "arjun", "version_command": ("-h",)},
    "paramspider": {"executable": "paramspider", "version_command": ("-h",)},
    "kiterunner": {"executable": "kr", "aliases": ("kiterunner",), "version_command": ("-v",)},
    "bbot": {"executable": "bbot", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "theharvester": {"executable": "theHarvester", "version_command": ("-h",)},
    "urlfinder": {"executable": "urlfinder", "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "nuclei": {"executable": "nuclei", "version_command": ("-version",), "version_regex": r"version\s*:?\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "3.0.0"},
    "dalfox": {"executable": "dalfox", "version_command": ("--version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "xssstrike": {"executable": "xsstrike", "version_command": ("-h",)},
    "sqlmap": {"executable": "sqlmap", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "1.6.0"},
    "ghauri": {"executable": "ghauri", "version_command": ("--version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "commix": {"executable": "commix", "version_command": ("-v",), "version_regex": r"Version\s*:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "interactsh": {"executable": "interactsh-client", "aliases": ("interactsh",), "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "tplmap": {"executable": "tplmap", "version_command": ("-h",)},
    "sstimap": {"executable": "sstimap", "version_command": ("--version",), "version_regex": r"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "graphqlmap": {"executable": "graphqlmap", "version_command": ("-h",)},
    "inql": {"executable": "inql", "version_command": ("-h",)},
    "gitleaks": {"executable": "gitleaks", "version_command": ("version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "8.16.0"},
    "trufflehog": {"executable": "trufflehog", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "3.60.0"},
    "semgrep": {"executable": "semgrep", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "zap": {"executable": "zaproxy", "aliases": ("zap.sh",), "version_command": ("-version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "mitmproxy": {"executable": "mitmproxy", "version_command": ("--version",), "version_regex": r"Mitmproxy:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "metasploit": {"executable": "msfconsole", "aliases": ("msf",), "version_command": ("--version",), "version_regex": r"Framework:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "searchsploit": {"executable": "searchsploit", "version_command": ("-h",)},
    "exploitdb": {"executable": "searchsploit", "version_command": ("-h",)},
    "nmap": {"executable": "nmap", "version_command": ("--version",), "version_regex": r"Nmap\s+version\s+([0-9]+\.[0-9]+)", "min_version": "7.80"},
    "naabu": {"executable": "naabu", "version_command": ("-version",), "version_regex": r"version\s+?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "2.3.0"},
    "masscan": {"executable": "masscan", "version_command": ("--version",), "version_regex": r"version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", "min_version": "1.3.0"},
    "rustscan": {"executable": "rustscan", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "testssl.sh": {"executable": "testssl.sh", "aliases": ("testssl",), "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    # -- python/package-tool binary specs (no version flag, help probe) -------
    "cewl": {"executable": "cewl", "version_command": ("--help",)},
    "dnsrecon": {"executable": "dnsrecon", "version_command": ("-h",)},
    "detect-secrets": {"executable": "detect-secrets", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "hashcat": {"executable": "hashcat", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "john": {"executable": "john", "aliases": ("john-the-ripper",), "version_command": (), "version_regex": r"version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "nikto": {"executable": "nikto", "version_command": ("-Version",), "version_regex": r"Nikto\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "osv-scanner": {"executable": "osv-scanner", "version_command": ("--version",), "version_regex": r"osv-scanner version:\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "prowler": {"executable": "prowler", "version_command": ("--version",), "version_regex": r"Prowler\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "scoutsuite": {"executable": "scout", "aliases": ("scoutsuite",), "version_command": ("--help",)},
    "sslscan": {"executable": "sslscan", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "wafw00f": {"executable": "wafw00f", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "wapiti": {"executable": "wapiti", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "spiderfoot": {"executable": "sf", "aliases": ("spiderfoot",), "version_command": ("-h",)},
    "trivy": {"executable": "trivy", "version_command": ("--version",), "version_regex": r"Version:\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "syft": {"executable": "syft", "version_command": ("version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "grype": {"executable": "grype", "version_command": ("version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "openvas": {"executable": "gvmd", "aliases": ("gvm-cli", "gvm"), "version_command": ("--version",)},
    "linkfinder": {"executable": "linkfinder", "version_command": ("-h",)},
    "secretfinder": {"executable": "secretfinder", "aliases": ("SecretFinder",), "version_command": ("-h",)},
    "xnlinkfinder": {"executable": "xnlinkfinder", "aliases": ("xnLinkFinder",), "version_command": ("-h",)},
    "gauplus": {"executable": "gauplus", "version_command": ("-h",)},
    "jsluice": {"executable": "jsluice", "version_command": ("-h",)},
    "xxeinjector": {"executable": "xxeinjector", "version_command": ("-h",)},
    "enum4linux-ng": {"executable": "enum4linux-ng", "version_command": ("-h",)},
    "netexec": {"executable": "nxc", "aliases": ("netexec",), "version_command": ("--version",), "version_regex": r"NetExec\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "impacket": {"executable": "impacket-smbclient", "aliases": ("secretsdump", "psexec"), "version_command": ("-h",)},
    "ldapsearch": {"executable": "ldapsearch", "version_command": ("-VV",), "version_regex": r"ldapsearch\s+([0-9]+\.[0-9]+)"},
    "rpcclient": {"executable": "rpcclient", "version_command": ("-V",), "version_regex": r"([0-9]+\.[0-9]+\.[0-9]+)"},
    "snmpwalk": {"executable": "snmpwalk", "version_command": ("-V",), "version_regex": r"version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "jwt-tool": {"executable": "jwt_tool", "aliases": ("jwt-tool",), "version_command": ("-h",)},
    "fping": {"executable": "fping", "version_command": ("-v",), "version_regex": r"([0-9]+\.[0-9]+)"},
    "arp-scan": {"executable": "arp-scan", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "unicornscan": {"executable": "unicornscan", "version_command": ("--version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "kube-bench": {"executable": "kube-bench", "version_command": ("version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    "codeql": {"executable": "codeql", "version_command": ("version",), "version_regex": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
}

#: Tools that are in-process adapters (no external binary is executed).
INPROCESS_TOOLS: frozenset[str] = frozenset(
    {
        "proof-replay",
        "dnspython",
        "javascript",
        "auth-analysis",
        "authorization-analysis",
        "cloud-analysis",
        "nvd-cve",
        "cisa-kev",
        "epss",
        "mitre-cwe",
        "vendor-advisory",
        "osv",
        "signature",
        "crawler",
        "payloadsallthethings",
        "seclists",
        "fuzzdb",
        "tcp-connect",
        "traceroute",
    }
)

#: Planner capability → ordered provider tool ids.
#: This is the single source of truth consumed by both the tool selection
#: engine and the readiness capability resolver (never duplicated elsewhere).
CAPABILITY_PROVIDERS: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("amass", "subfinder", "assetfinder", "findomain", "bbot", "theharvester"),
    "subdomain_enumeration": ("subfinder", "amass", "assetfinder", "findomain", "bbot", "theharvester"),
    "dns_enumeration": ("dnsx", "massdns", "shuffledns", "dnspython"),
    "port_discovery": ("nmap", "rustscan", "naabu", "masscan"),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb", "httpx"),
    "certificate_enumeration": ("findomain", "crt-sh"),
    "endpoint_enumeration": ("httpx", "katana", "gospider", "hakrawler", "gau", "waybackurls"),
    "content_discovery": ("ffuf", "gobuster", "feroxbuster", "dirsearch"),
    "parameter_discovery": ("arjun", "paramspider", "ffuf"),
    "api_mapping": ("katana", "kiterunner"),
    "authentication_analysis": ("httpx", "nuclei"),
    "authorization_analysis": ("httpx", "nuclei"),
    "vulnerability_scanning": ("nuclei", "nikto", "wapiti"),
    "sql_injection": ("sqlmap", "ghauri"),
    "xss": ("dalfox", "xssstrike"),
    "ssrf": ("ffuf", "nuclei"),
    "ssti": ("sstimap", "tplmap"),
    "xxe": ("xxeinjector", "nuclei"),
    "lfi": ("ffuf", "nuclei"),
    "rce": ("nuclei", "commix", "metasploit"),
    "idor": ("ffuf", "nuclei"),
    "api_security": ("nuclei", "kiterunner"),
    "graphql_security": ("inql", "graphqlmap"),
    "secret_detection": ("trufflehog", "gitleaks", "detect-secrets"),
    "dependency_check": ("osv-scanner", "trivy"),
    "cloud_ownership_mapping": ("prowler", "scoutsuite"),
    "proof_validation": ("proof-replay",),
    "replay": ("proof-replay",),
}

#: Default capability importance for mission preflight gating. ``required``
#: capabilities block a mission when no provider is available; ``recommended``
#: and ``optional`` capabilities only degrade it.
CAPABILITY_LEVELS: dict[str, CapabilityLevel] = {
    "asset_discovery": CapabilityLevel.REQUIRED,
    "subdomain_enumeration": CapabilityLevel.REQUIRED,
    "dns_enumeration": CapabilityLevel.REQUIRED,
    "port_discovery": CapabilityLevel.REQUIRED,
    "service_detection": CapabilityLevel.REQUIRED,
    "technology_fingerprint": CapabilityLevel.REQUIRED,
    "certificate_enumeration": CapabilityLevel.OPTIONAL,
    "endpoint_enumeration": CapabilityLevel.REQUIRED,
    "content_discovery": CapabilityLevel.REQUIRED,
    "parameter_discovery": CapabilityLevel.REQUIRED,
    "api_mapping": CapabilityLevel.OPTIONAL,
    "authentication_analysis": CapabilityLevel.RECOMMENDED,
    "authorization_analysis": CapabilityLevel.RECOMMENDED,
    "vulnerability_scanning": CapabilityLevel.RECOMMENDED,
    "sql_injection": CapabilityLevel.RECOMMENDED,
    "xss": CapabilityLevel.RECOMMENDED,
    "ssrf": CapabilityLevel.RECOMMENDED,
    "ssti": CapabilityLevel.RECOMMENDED,
    "xxe": CapabilityLevel.RECOMMENDED,
    "lfi": CapabilityLevel.RECOMMENDED,
    "rce": CapabilityLevel.RECOMMENDED,
    "idor": CapabilityLevel.RECOMMENDED,
    "api_security": CapabilityLevel.RECOMMENDED,
    "graphql_security": CapabilityLevel.OPTIONAL,
    "secret_detection": CapabilityLevel.OPTIONAL,
    "dependency_check": CapabilityLevel.OPTIONAL,
    "cloud_ownership_mapping": CapabilityLevel.OPTIONAL,
    "proof_validation": CapabilityLevel.REQUIRED,
    "replay": CapabilityLevel.OPTIONAL,
}

#: Installation profiles → tool ids. The ``minimal`` profile is the base
#: HunterX environment (in-process adapters only — no external installs).
PROFILE_TOOLS: dict[str, tuple[str, ...]] = {
    "minimal": tuple(sorted(INPROCESS_TOOLS)),
    "recon": (
        "subfinder", "amass", "assetfinder", "findomain", "dnsx", "massdns",
        "shuffledns", "nmap", "naabu", "masscan", "rustscan", "httpx",
        "whatweb", "katana", "gospider", "hakrawler", "gau", "waybackurls",
        "ffuf", "feroxbuster", "gobuster", "dirsearch", "arjun", "paramspider",
        "kiterunner",
    ),
    "network": ("nmap", "naabu", "masscan", "rustscan", "massdns", "dnsx"),
    "web": (
        "httpx", "katana", "whatweb", "gospider", "hakrawler", "gau",
        "waybackurls", "ffuf", "feroxbuster", "gobuster", "dirsearch", "arjun",
        "paramspider", "kiterunner", "nuclei", "dalfox", "xssstrike", "sqlmap",
        "ghauri", "commix", "tplmap", "sstimap", "graphqlmap", "inql",
        "interactsh", "xxeinjector",
    ),
    "vulnerability": (
        "nuclei", "sqlmap", "ghauri", "dalfox", "xssstrike", "commix", "tplmap",
        "sstimap", "xxeinjector", "graphqlmap", "inql", "interactsh",
        "gitleaks", "trufflehog", "semgrep", "zap", "mitmproxy", "osv-scanner",
        "trivy", "metasploit",
    ),
    "full": tuple(
        dict.fromkeys(
            [
                *INSTALL_METHODS.keys(),
                "nmap",
                "masscan",
                "rustscan",
                "whatweb",
                "gobuster",
                "metasploit",
                "searchsploit",
                "nikto",
                "sqlmap",
                "dirsearch",
                "arjun",
                "paramspider",
                "ghauri",
                "commix",
                "sstimap",
                "graphqlmap",
                "inql",
                "xssstrike",
                "tplmap",
                "mitmproxy",
                "semgrep",
                "wapiti",
                "detect-secrets",
                "dnsrecon",
                "zap",
                "wafw00f",
                "testssl.sh",
                "sslscan",
                "openvas",
                "osv-scanner",
                "trivy",
                "prowler",
                "scoutsuite",
                "hashcat",
                "john",
                "cewl",
            ]
        )
    ),
}


def install_methods_for(tool_id: str, platform: PlatformInfo) -> tuple[InstallMethod, ...]:
    """Return the trusted install methods for ``tool_id`` on ``platform``.

    Methods whose platform list does not match the current environment are
    excluded so the provisioner never attempts an incompatible install.
    """
    candidates = INSTALL_METHODS.get(tool_id, ())
    os_name = platform.os
    if os_name == "linux" and platform.wsl:
        # Under WSL the Linux package manager is authoritative.
        os_name = "linux"
    return tuple(
        method
        for method in candidates
        if os_name in method.platforms
        or (method.platforms == ("linux",) and os_name == "linux")
    )


#: Tools HunterX publicly claims to integrate (the supported external toolchain).
#: The integration audit and CI completeness gate are enforced against this set.
CLAIMED_EXTERNAL_TOOLS: tuple[str, ...] = (
    "nmap", "naabu", "masscan", "rustscan", "amass", "subfinder", "assetfinder",
    "findomain", "dnsx", "massdns", "shuffledns", "httpx", "whatweb", "katana",
    "gospider", "hakrawler", "gau", "waybackurls", "ffuf", "feroxbuster",
    "gobuster", "dirsearch", "arjun", "paramspider", "kiterunner", "nuclei",
    "dalfox", "xssstrike", "sqlmap", "ghauri", "commix", "interactsh", "tplmap",
    "sstimap", "graphqlmap", "inql", "gitleaks", "trufflehog", "semgrep", "zap",
    "mitmproxy", "metasploit", "searchsploit",
)

__all__ = [
    "CAPABILITY_LEVELS",
    "CAPABILITY_PROVIDERS",
    "CLAIMED_EXTERNAL_TOOLS",
    "INPROCESS_TOOLS",
    "INSTALL_METHODS",
    "PROFILES",
    "PROFILE_TOOLS",
    "TOOL_BINARY_SPECS",
    "install_methods_for",
]
