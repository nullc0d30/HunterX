---
layout: default
title: Tool Ecosystem — HunterX v7
keywords: HunterX tools, open source penetration testing tools, bug bounty tools, bug hunting tools, recon tools, web security tools, API security tools, vulnerability scanners, red team tools, security testing tools, OSINT reconnaissance tools, fuzzing tools, security research tools, HunterX integrations
description: >-
  The HunterX v7 tool ecosystem: the open-source security tools HunterX
  integrates with, executes, parses, normalizes and correlates. Recon, port
  scanning, crawling, fuzzing, parameter discovery, vulnerability detection and
  validation, secrets, SAST, proxies, exploitation and knowledge resources.
  Integration status is documented per tool — never overclaimed.
---

# Tool Ecosystem

HunterX is **built to work with the security-tooling ecosystem**. It does not
attempt to replace every security capability itself. Instead, it orchestrates
open-source security tools: it executes them with structured contracts, parses
and normalizes their output into canonical observations, correlates results,
reasons over hypotheses, validates with evidence, engineers and replays
proofs/PoCs, and produces professional reports.

The canonical integration registry is the
[v7 toolchain intelligence](/v7-full-toolchain-intelligence/) architecture and
the machine-readable
[`full-toolchain-intelligence.json`](https://github.com/nullc0d30/HunterX/blob/main/capabilities/full-toolchain-intelligence.json)
capability manifest.

## Integration status

Every tool below is labeled accurately. **HunterX never claims direct
execution it does not implement.**

- **Integrated &middot; fully supported** — structured execution, versioned
  parser and normalizer, canonical observations.
- **Integrated &middot; partial support** — parser/normalizer or adapter with
  documented limitations.
- **Integrated &middot; execution only** — structured execution with a guarded
  adapter (never arbitrary subprocess).
- **Planned / Resource** — registered as a knowledge resource or known tool in
  the manifest; direct execution is not claimed.

## How tool output becomes findings

For every integrated tool, HunterX applies the canonical pipeline:

```
tool output → parser → normalizer → canonical observation → correlation →
hypothesis → verification → evidence → proof → PoC → replay → report-ready finding
```

Tool results are **never raw verdicts**: output is parsed and normalized into
canonical observations before it can influence a finding.

### Recon / Asset Discovery

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Amass](https://github.com/owasp-amass/amass) | subdomain-enumeration, asn-enumeration | subdomain-enumeration, asn-enumeration, org-enumeration, asset-discovery | **Integrated** &middot; fully supported |
| [Assetfinder](https://github.com/tomnomnom/assetfinder) | subdomain-enumeration | subdomain-enumeration | **Integrated** &middot; fully supported |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | subdomain-enumeration, asset-discovery | subdomain-enumeration, asset-discovery, osint | **Integrated** &middot; fully supported |
| [Crobat](https://github.com/Cgboal/SonarSearch) | subdomain-enumeration, historical-url-discovery | subdomain-enumeration, historical-url-discovery | **Integrated** &middot; partial support |
| [crt.sh Certificate Transparency](https://crt.sh) | certificate-enumeration, subdomain-enumeration | certificate-enumeration, subdomain-enumeration | **Integrated** &middot; partial support |
| [Findomain](https://github.com/Findomain/Findomain) | subdomain-enumeration, certificate-enumeration | subdomain-enumeration, certificate-enumeration, dns-intelligence | **Integrated** &middot; fully supported |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | osint, asset-discovery | osint, asset-discovery, org-enumeration, asn-enumeration | **Integrated** &middot; partial support |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | subdomain-enumeration, asset-discovery | subdomain-enumeration, asset-discovery | **Integrated** &middot; fully supported |
| [theHarvester](https://github.com/laramies/theHarvester) | subdomain-enumeration, osint | subdomain-enumeration, osint, org-enumeration, asset-discovery | **Integrated** &middot; fully supported |

### Network / Port Scanning

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [arp-scan](https://github.com/royhills/arp-scan) | host-discovery, network-discovery | host-discovery, network-discovery | Planned / Resource |
| [fping](https://github.com/schweikert/fping) | host-discovery | host-discovery | Planned / Resource |
| [Masscan](https://github.com/robertdavidgraham/masscan) | port-discovery | port-discovery | **Integrated** &middot; fully supported |
| [Naabu](https://github.com/projectdiscovery/naabu) | port-discovery, host-discovery | port-discovery, host-discovery | **Integrated** &middot; fully supported |
| [Nmap](https://github.com/nmap/nmap) | port-discovery, service-discovery | port-discovery, service-discovery, version-detection, os-detection, network-discovery | **Integrated** &middot; fully supported |
| [RustScan](https://github.com/RustScan/RustScan) | port-discovery | port-discovery | **Integrated** &middot; partial support |
| Unicornscan | port-discovery | port-discovery | Planned / Resource |

### HTTP / Crawling / Discovery

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [HTTPx](https://github.com/projectdiscovery/httpx) | http-probing, technology-detection | http-probing, technology-detection, http-configuration-analysis | **Integrated** &middot; fully supported |
| [Nikto](https://github.com/sullo/nikto) | web-server-analysis, http-configuration-analysis | web-server-analysis, http-configuration-analysis | **Integrated** &middot; partial support |
| [SSLScan](https://github.com/rbsec/sslscan) | tls-analysis | tls-analysis | Planned / Resource |
| [testssl.sh](https://github.com/drwetter/testssl.sh) | tls-analysis, http-configuration-analysis | tls-analysis, http-configuration-analysis | Planned / Resource |
| [Wafw00f](https://github.com/EnableSecurity/wafw00f) | waf-detection | waf-detection | Planned / Resource |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | technology-detection, web-server-analysis | technology-detection, web-server-analysis | **Integrated** &middot; fully supported |

### Crawling / URL Discovery

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [GAU](https://github.com/lc/gau) | historical-url-discovery, url-discovery | historical-url-discovery, url-discovery | **Integrated** &middot; partial support |
| [gauplus](https://github.com/bp0lr/gauplus) | historical-url-discovery, url-discovery | historical-url-discovery, url-discovery | **Integrated** &middot; partial support |
| [Gospider](https://github.com/jaeles-project/gospider) | crawling, url-discovery | crawling, url-discovery, javascript-discovery | **Integrated** &middot; partial support |
| [Hakrawler](https://github.com/hakluke/hakrawler) | crawling, url-discovery | crawling, url-discovery | **Integrated** &middot; partial support |
| [Katana](https://github.com/projectdiscovery/katana) | crawling, url-discovery | crawling, url-discovery, endpoint-discovery | **Integrated** &middot; fully supported |
| URLFinder | historical-url-discovery, url-discovery | historical-url-discovery, url-discovery | **Integrated** &middot; partial support |
| [Waybackurls](https://github.com/tomnomnom/waybackurls) | historical-url-discovery | historical-url-discovery | **Integrated** &middot; partial support |

### Fuzzing / Content Discovery

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Dirsearch](https://github.com/maurosoria/dirsearch) | directory-enumeration, file-enumeration | directory-enumeration, file-enumeration | **Integrated** &middot; partial support |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | content-discovery, directory-enumeration | content-discovery, directory-enumeration, file-enumeration | **Integrated** &middot; partial support |
| [FFUF](https://github.com/ffuf/ffuf) | content-discovery, directory-enumeration | content-discovery, directory-enumeration, file-enumeration, vhost-enumeration | **Integrated** &middot; fully supported |
| [Gobuster](https://github.com/OJ/gobuster) | directory-enumeration, file-enumeration | directory-enumeration, file-enumeration, vhost-enumeration | **Integrated** &middot; partial support |

### Parameter / Endpoint Discovery

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Arjun](https://github.com/s0md3v/Arjun) | parameter-discovery, get-parameter-discovery | parameter-discovery, get-parameter-discovery, post-parameter-discovery | **Integrated** &middot; partial support |
| [ParamSpider](https://github.com/devanshbatham/ParamSpider) | parameter-discovery, historical-parameter-discovery | parameter-discovery, historical-parameter-discovery | **Integrated** &middot; partial support |

### Vulnerability Detection / Validation

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Nuclei](https://github.com/projectdiscovery/nuclei) | cve-detection, misconfiguration-detection | cve-detection, misconfiguration-detection, web-vulnerability-detection, exposure-detection | **Integrated** &middot; fully supported |
| [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) | cve-detection, misconfiguration-detection | cve-detection, misconfiguration-detection, network-vulnerability-detection | Planned / Resource |
| [Wapiti](https://github.com/wapiti-scanner/wapiti) | web-vulnerability-detection | web-vulnerability-detection | **Integrated** &middot; partial support |

### Injection Detection / Validation

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Commix](https://github.com/commixproject/commix) | command-injection-detection, command-injection-validation | command-injection-detection, command-injection-validation | **Integrated** &middot; partial support |
| [Dalfox](https://github.com/hahwul/dalfox) | xss-discovery, reflection-analysis | xss-discovery, reflection-analysis, parameter-analysis, xss-validation | **Integrated** &middot; partial support |
| [Ghauri](https://github.com/r0oth3x49/ghauri) | sql-injection-detection, sql-injection-validation | sql-injection-detection, sql-injection-validation, database-fingerprinting | **Integrated** &middot; partial support |
| [SQLmap](https://github.com/sqlmapproject/sqlmap) | sql-injection-detection, sql-injection-validation | sql-injection-detection, sql-injection-validation, database-fingerprinting | **Integrated** &middot; partial support |
| [SSTImap](https://github.com/vladko312/SSTImap) | ssti-detection, ssti-validation | ssti-detection, ssti-validation, template-engine-identification | **Integrated** &middot; partial support |
| [Tplmap](https://github.com/epinna/tplmap) | ssti-detection, template-engine-identification | ssti-detection, template-engine-identification | **Integrated** &middot; partial support |
| [XSStrike](https://github.com/s0md3v/XSStrike) | xss-discovery, dom-analysis | xss-discovery, dom-analysis, reflection-analysis | **Integrated** &middot; partial support |
| [XXEinjector](https://github.com/enjoiz/XXEinjector) | xxe-detection, xxe-validation | xxe-detection, xxe-validation, oob-xml-interaction | **Integrated** &middot; partial support |

### OOB / Callback

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Interactsh](https://github.com/projectdiscovery/interactsh) | oob-callback, dns-callback | oob-callback, dns-callback, http-callback, smtp-callback, interaction-correlation | **Integrated** &middot; partial support |

### Source / Code / Secret Analysis

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [detect-secrets](https://github.com/Yelp/detect-secrets) | secret-discovery, credential-discovery | secret-discovery, credential-discovery, token-discovery | **Integrated** &middot; partial support |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | secret-discovery, credential-discovery | secret-discovery, credential-discovery, token-discovery, key-discovery | **Integrated** &middot; fully supported |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | secret-discovery, credential-discovery | secret-discovery, credential-discovery, token-discovery | **Integrated** &middot; partial support |

### SAST

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [CodeQL CLI](https://github.com/github/codeql-cli-binaries) | sast, code-flow-analysis | sast, code-flow-analysis, taint-analysis, vulnerability-pattern-detection | Planned / Resource |
| [Semgrep](https://github.com/semgrep/semgrep) | sast, code-pattern-analysis | sast, code-pattern-analysis, vulnerability-pattern-detection | **Integrated** &middot; partial support |

### Proxy / Web Security

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | http-interception, request-replay | http-interception, request-replay, response-analysis, traffic-capture | **Integrated** &middot; partial support |
| [OWASP ZAP](https://github.com/zaproxy/zaproxy) | http-interception, request-replay | http-interception, request-replay, response-analysis, active-testing | **Integrated** &middot; partial support |

### Exploitation / Security Research

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [ExploitDB](https://gitlab.com/exploit-database/exploitdb) | exploit-research, cve-research | exploit-research, cve-research, version-mapping | **Integrated** &middot; partial support |
| [Metasploit Framework](https://github.com/rapid7/metasploit-framework) | exploit-validation, service-validation | exploit-validation, service-validation, payload-capability, session-management | **Integrated** &middot; execution only |
| [SearchSploit / ExploitDB](https://gitlab.com/exploit-database/exploitdb) | exploit-research, cve-research | exploit-research, cve-research, version-mapping | **Integrated** &middot; partial support |

### Knowledge / Payload Resources

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) | attack-patterns, payload-intelligence | attack-patterns, payload-intelligence, response-patterns, discovery-dictionaries | **Integrated** &middot; partial support |
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | payload-intelligence, payload-generation | payload-intelligence, payload-generation, vulnerability-class-payloads | **Integrated** &middot; partial support |
| [SecLists](https://github.com/danielmiessler/SecLists) | wordlist-provider, content-discovery-aid | wordlist-provider, content-discovery-aid, dns-bruteforce-aid, password-audit-aid | **Integrated** &middot; partial support |

### API / GraphQL

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) | graphql-analysis, graphql-introspection | graphql-analysis, graphql-introspection, query-analysis | **Integrated** &middot; partial support |
| [InQL](https://github.com/doyensec/inql) | graphql-analysis, graphql-introspection | graphql-analysis, graphql-introspection, query-analysis | **Integrated** &middot; partial support |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | jwt-analysis, authentication-analysis | jwt-analysis, authentication-analysis | Planned / Resource |
| [Kiterunner](https://github.com/assetnote/kiterunner) | api-discovery, content-discovery | api-discovery, content-discovery | **Integrated** &middot; partial support |
| OpenAPI / Swagger parser | openapi-analysis, api-discovery | openapi-analysis, api-discovery, api-parameter-analysis | **Integrated** &middot; partial support |
| Postman collection parser | api-discovery, api-parameter-analysis | api-discovery, api-parameter-analysis | **Integrated** &middot; partial support |

### JavaScript Analysis

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [JSluice](https://github.com/BishopFox/jsluice) | javascript-analysis, endpoint-extraction | javascript-analysis, endpoint-extraction, secret-indicator-discovery, source-map-discovery | **Integrated** &middot; partial support |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | javascript-analysis, endpoint-extraction | javascript-analysis, endpoint-extraction | **Integrated** &middot; partial support |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | javascript-analysis, secret-indicator-discovery | javascript-analysis, secret-indicator-discovery | **Integrated** &middot; partial support |
| [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) | javascript-analysis, endpoint-extraction | javascript-analysis, endpoint-extraction, parameter-discovery | **Integrated** &middot; partial support |

### Cloud Assessment

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | aws-security, azure-security | aws-security, azure-security, gcp-security, cloud-asset-discovery, cloud-misconfiguration | **Integrated** &middot; partial support |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | aws-security, azure-security | aws-security, azure-security, gcp-security, cloud-misconfiguration | Planned / Resource |

### Container / Supply Chain

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [Grype](https://github.com/anchore/grype) | container-analysis, cve-analysis | container-analysis, cve-analysis, dependency-analysis | **Integrated** &middot; partial support |
| [kube-bench](https://github.com/aquasecurity/kube-bench) | kubernetes-security, k8s-configuration-analysis | kubernetes-security, k8s-configuration-analysis | Planned / Resource |
| [Syft](https://github.com/anchore/syft) | sbom-generation, container-analysis | sbom-generation, container-analysis, dependency-analysis | **Integrated** &middot; partial support |
| [Trivy](https://github.com/aquasecurity/trivy) | container-analysis, image-analysis | container-analysis, image-analysis, sbom, dependency-analysis | **Integrated** &middot; partial support |

### Dependency Scanning

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [OSV-Scanner](https://github.com/google/osv-scanner) | dependency-analysis, vulnerability-mapping | dependency-analysis, vulnerability-mapping | **Integrated** &middot; partial support |

### Enterprise / Active Directory

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) | smb-enumeration, windows-enumeration | smb-enumeration, windows-enumeration, domain-enumeration | Planned / Resource |
| [Impacket](https://github.com/fortra/impacket) | smb-enumeration, kerberos-enumeration | smb-enumeration, kerberos-enumeration, domain-enumeration | Planned / Resource |
| [ldapsearch](https://www.openldap.org/software/man.cgi?query=ldapsearch) | ldap-enumeration, active-directory-intelligence | ldap-enumeration, active-directory-intelligence | Planned / Resource |
| [NetExec](https://github.com/Pennyw0rth/NetExec) | smb-enumeration, windows-enumeration | smb-enumeration, windows-enumeration, ldap-enumeration, domain-enumeration | Planned / Resource |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | smb-enumeration, windows-enumeration | smb-enumeration, windows-enumeration | Planned / Resource |

### SNMP

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [snmpwalk](https://github.com/net-snmp/net-snmp) | snmp-enumeration, network-device-enumeration | snmp-enumeration, network-device-enumeration | Planned / Resource |

### Password / Wordlist

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [CeWL](https://github.com/digininja/CeWL) | wordlist-generation, content-discovery-aid | wordlist-generation, content-discovery-aid, custom-wordlists | **Integrated** &middot; partial support |
| [Hashcat](https://github.com/hashcat/hashcat) | password-cracking, hash-analysis | password-cracking, hash-analysis, hash-modes | Planned / Resource |
| [John the Ripper](https://github.com/openwall/john) | password-cracking, hash-analysis | password-cracking, hash-analysis | Planned / Resource |

### DNS & Resolution

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| [dnspython](https://github.com/rthalley/dnspython) | dns-resolution, record-enumeration | dns-resolution, record-enumeration | **Integrated** &middot; fully supported |
| [DNSrecon](https://github.com/darkoperator/dnsrecon) | dns-enumeration, brute-force-dns | dns-enumeration, brute-force-dns, record-enumeration | Planned / Resource |
| [DNSx](https://github.com/projectdiscovery/dnsx) | dns-resolution, record-enumeration | dns-resolution, record-enumeration, wildcard-detection | **Integrated** &middot; fully supported |
| [MassDNS](https://github.com/blechschmidt/massdns) | dns-resolution | dns-resolution | **Integrated** &middot; partial support |
| [Shuffledns](https://github.com/projectdiscovery/shuffledns) | dns-resolution, brute-force-dns | dns-resolution, brute-force-dns | **Integrated** &middot; partial support |

### Proof / Replay

| Tool | Primary role | Capabilities fed to HunterX | Status |
|---|---|---|---|
| Proof Replay | safe-validation, proof-replay | safe-validation, proof-replay, impact-statement | **Integrated** &middot; fully supported |



HunterX integrates with and leverages the third-party open-source projects
listed above. It does not claim ownership of them. Each project keeps its own
license and attribution, which is preserved in
[THIRD_PARTY_NOTICES](https://github.com/nullc0d30/HunterX/blob/main/THIRD_PARTY_NOTICES).
Tool names, trademarks and descriptions are used only to document
interoperability.

## Related

- [Vulnerability Proof & PoC](/v7-vulnerability-proof-and-poc/) — how proof
  contracts validate hypotheses
- [Full Toolchain Intelligence](/v7-full-toolchain-intelligence/) — the
  integration architecture
- [Tool Integration SDK](/v7-tool-integration-sdk/) — the adapter SDK
- [Features](/features/) — platform capabilities