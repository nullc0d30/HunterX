# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability engine.

Classifies, registers and searches capabilities. A capability is a discrete,
nameable thing a tool can do (recon, dns, subdomain discovery, ...). The
engine keeps a searchable catalog of capability definitions and knows which
tools provide which capability.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import ToolCapability
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.taxonomy import ToolTaxonomy

#: Canonical capability descriptions for the taxonomy's built-in capabilities.
_CANONICAL_DESCRIPTIONS: dict[str, str] = {
    "subdomain-discovery": "Discover subdomains of a root domain",
    "host-discovery": "Discover live hosts in a scope",
    "dns-records": "Enumerate DNS records (A, AAAA, CNAME, MX, TXT)",
    "port-scanning": "Scan hosts for open TCP/UDP ports",
    "service-fingerprint": "Identify services and versions on open ports",
    "http-enumeration": "Enumerate HTTP endpoints and responses",
    "technology-detection": "Detect web technologies and frameworks",
    "web-crawling": "Crawl web applications to discover endpoints",
    "directory-discovery": "Discover hidden directories and files",
    "parameter-discovery": "Discover and fuzz query/body parameters",
    "javascript-analysis": "Analyze client-side JavaScript for secrets and endpoints",
    "secrets-detection": "Detect secrets and credentials in content",
    "ssl-analysis": "Analyze TLS/SSL certificates and configuration",
    "certificate-lookup": "Query certificate transparency logs",
    "dns-history": "Query historical DNS records",
    "whois-lookup": "Perform WHOIS lookups",
    "vulnerability-scan": "Scan for known vulnerabilities",
    "cve-detection": "Detect specific CVEs",
    "web-fuzzing": "Fuzz web endpoints for behaviors",
    "sqli-detection": "Detect SQL injection",
    "xss-detection": "Detect cross-site scripting",
    "ssti-detection": "Detect server-side template injection",
    "api-discovery": "Discover API endpoints and schemas",
    "api-fuzzing": "Fuzz API endpoints and parameters",
    "graphql-testing": "Test GraphQL introspection and mutations",
    "misconfiguration": "Detect security misconfigurations",
    "weak-config": "Detect weak configuration values",
    "exposed-services": "Detect exposed network services",
    "cloud-assessment": "Assess cloud account and service posture",
    "cloud-permission-audit": "Audit cloud IAM permissions",
    "storage-audit": "Audit cloud storage permissions and exposure",
    "container-assessment": "Assess container and image posture",
    "image-scan": "Scan container images for vulnerabilities",
    "k8s-audit": "Audit Kubernetes configuration",
    "serverless-audit": "Audit serverless functions and permissions",
    "active-directory": "Assess Active Directory posture",
    "ldap-enumeration": "Enumerate LDAP directories",
    "kerberos-attacks": "Test Kerberos authentication paths",
    "identity-enumeration": "Enumerate identity and account information",
    "token-analysis": "Analyze authentication tokens",
    "static-analysis": "Statically analyze source code",
    "sast": "Run static application security testing",
    "secrets-scan": "Scan repositories for secrets",
    "binary-analysis": "Analyze compiled binaries",
    "exploit-development": "Develop or validate exploits",
    "packet-analysis": "Analyze network packets",
    "proxy-inspection": "Inspect proxied traffic",
    "reporting": "Generate structured reports",
    "evidence-capture": "Capture supporting evidence",
    "sarif-export": "Export results as SARIF",
}


class CapabilityEngine:
    """Searchable catalog of capabilities and their providers.

    Usage::

        engine = CapabilityEngine(registry, taxonomy)
        engine.sync_taxonomy()                      # seed canonical capabilities
        engine.providers("subdomain-discovery")     # -> ["subfinder"]
    """

    def __init__(self, registry: ToolIntelligenceRegistry, taxonomy: ToolTaxonomy) -> None:
        self._registry = registry
        self._taxonomy = taxonomy

    def sync_taxonomy(self) -> None:
        """Seed capability definitions from the taxonomy into the registry."""
        for capability_id in self._taxonomy.capabilities():
            if self._registry.get_capability(capability_id) is not None:
                continue
            category, subcategory = self._taxonomy.classify(capability_id)
            self._registry.register_capability(
                ToolCapability(
                    capability_id=capability_id,
                    name=capability_id.replace("-", " ").title(),
                    category=category,
                    subcategory=subcategory,
                    description=_CANONICAL_DESCRIPTIONS.get(capability_id, ""),
                    techniques=self._taxonomy.techniques_for(capability_id),
                    missions=self._taxonomy.missions_for(capability_id),
                )
            )

    def register(self, capability: ToolCapability) -> None:
        """Register a custom capability definition."""
        self._registry.register_capability(capability)

    def get(self, capability_id: str) -> ToolCapability | None:
        """Return a capability definition or ``None``."""
        return self._registry.get_capability(capability_id)

    def capabilities(self) -> list[str]:
        """Return the sorted list of known capability ids."""
        return sorted(cap.capability_id for cap in self._registry.list_capabilities())

    def search(self, term: str, *, limit: int = 25) -> list[ToolCapability]:
        """Search capability definitions by id/name/description."""
        needle = term.lower()
        matches = [
            capability
            for capability in self._registry.list_capabilities()
            if needle in capability.capability_id
            or needle in capability.name.lower()
            or needle in capability.description.lower()
            or needle in capability.category
            or needle in capability.subcategory
        ]
        return matches[:limit]

    def by_category(self, category: str) -> list[ToolCapability]:
        """Return capabilities classified under ``category``."""
        return [
            capability
            for capability in self._registry.list_capabilities()
            if capability.category == category
        ]

    def providers(self, capability_id: str) -> list[str]:
        """Return tool ids that provide ``capability_id``."""
        return self._registry.providers_for(capability_id)

    def capabilities_for(self, tool_id: str) -> list[str]:
        """Return capability ids provided by ``tool_id``."""
        return self._registry.capabilities_for(tool_id)
