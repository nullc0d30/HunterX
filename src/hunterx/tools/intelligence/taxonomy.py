# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool taxonomy.

A hierarchical classification of everything HunterX understands about tools:
category → subcategory → capability → technique → mission. The taxonomy is
data-driven so new capabilities can be added without changing the engine.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import ToolTaxonomyNode

#: Canonical taxonomy tree. Keys are category ids; values map subcategory ids
#: to their capability ids. Techniques and missions are attached per
#: capability by the capability engine.
_TAXONOMY: dict[str, dict[str, list[str]]] = {
    "recon": {
        "dns": ["subdomain-discovery", "host-discovery", "dns-records"],
        "network": ["port-scanning", "service-fingerprint"],
        "http": [
            "http-enumeration",
            "technology-detection",
            "web-crawling",
            "directory-discovery",
            "parameter-discovery",
            "javascript-analysis",
            "secrets-detection",
            "ssl-analysis",
        ],
        "osint": ["certificate-lookup", "dns-history", "whois-lookup"],
    },
    "assessment": {
        "vulnerability": ["vulnerability-scan", "cve-detection"],
        "web": ["web-fuzzing", "sqli-detection", "xss-detection", "ssti-detection"],
        "api": ["api-discovery", "api-fuzzing", "graphql-testing"],
        "infrastructure": ["misconfiguration", "weak-config", "exposed-services"],
    },
    "cloud": {
        "iaas": ["cloud-assessment", "cloud-permission-audit", "storage-audit"],
        "container": ["container-assessment", "image-scan", "k8s-audit"],
        "serverless": ["serverless-audit"],
    },
    "directory": {
        "ad": ["active-directory", "ldap-enumeration", "kerberos-attacks"],
        "identity": ["identity-enumeration", "token-analysis"],
    },
    "analysis": {
        "code": ["static-analysis", "sast", "secrets-scan"],
        "binary": ["binary-analysis", "exploit-development"],
        "traffic": ["packet-analysis", "proxy-inspection"],
    },
    "reporting": {
        "output": ["reporting", "evidence-capture", "sarif-export"],
    },
}

#: Canonical technique ids attached to capabilities that map to them.
_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "subdomain-discovery": ("T1596",),
    "host-discovery": ("T1590",),
    "port-scanning": ("T1595",),
    "service-fingerprint": ("T1595",),
    "technology-detection": ("T1592",),
    "web-crawling": ("T1593",),
    "directory-discovery": ("T1593",),
    "secrets-detection": ("T1552",),
    "ssl-analysis": ("T1595",),
    "vulnerability-scan": ("T1595",),
    "active-directory": ("T1069",),
    "kerberos-attacks": ("T1558",),
}

#: Canonical mission profiles that consume each capability.
_MISSIONS: dict[str, tuple[str, ...]] = {
    "subdomain-discovery": ("external-pentest", "continuous", "bug-bounty"),
    "port-scanning": ("external-pentest", "internal-pentest", "continuous"),
    "vulnerability-scan": ("web-security", "api-security", "external-pentest"),
    "web-crawling": ("web-security", "bug-bounty"),
    "technology-detection": ("web-security", "api-security", "bug-bounty"),
    "cloud-assessment": ("cloud-security",),
    "container-assessment": ("cloud-security", "container-security"),
    "active-directory": ("internal-pentest", "ad-security"),
    "reporting": ("all",),
}


class ToolTaxonomy:
    """Data-driven hierarchical tool taxonomy.

    The taxonomy classifies categories, subcategories, capabilities,
    techniques and missions so every tool can be classified without touching
    the core engine.
    """

    def __init__(self) -> None:
        self._root = self._build_root()

    @staticmethod
    def _build_root() -> ToolTaxonomyNode:
        categories: list[ToolTaxonomyNode] = []
        for category_id, subcategories in _TAXONOMY.items():
            sub_nodes: list[ToolTaxonomyNode] = []
            for subcategory_id, capability_ids in subcategories.items():
                cap_nodes = [
                    ToolTaxonomyNode(
                        id=capability_id,
                        name=capability_id.replace("-", " ").title(),
                        kind="capability",
                    )
                    for capability_id in capability_ids
                ]
                sub_nodes.append(
                    ToolTaxonomyNode(
                        id=subcategory_id,
                        name=subcategory_id.replace("-", " ").title(),
                        kind="subcategory",
                        children=tuple(cap_nodes),
                    )
                )
            categories.append(
                ToolTaxonomyNode(
                    id=category_id,
                    name=category_id.title(),
                    kind="category",
                    children=tuple(sub_nodes),
                )
            )
        return ToolTaxonomyNode(id="root", name="Tool Taxonomy", kind="root", children=tuple(categories))

    @property
    def root(self) -> ToolTaxonomyNode:
        """Return the taxonomy root node."""
        return self._root

    def capabilities(self) -> list[str]:
        """Return every known capability id in the taxonomy."""
        result: list[str] = []

        def _collect(node: ToolTaxonomyNode) -> None:
            if node.kind == "capability":
                result.append(node.id)
            for child in node.children:
                _collect(child)

        _collect(self._root)
        return result

    def categories(self) -> list[str]:
        """Return the taxonomy category ids."""
        return [child.id for child in self._root.children]

    def subcategories(self, category_id: str) -> list[str]:
        """Return subcategory ids under ``category_id``."""
        node = self._root.find(category_id)
        if node is None:
            return []
        return [child.id for child in node.children]

    def techniques_for(self, capability_id: str) -> tuple[str, ...]:
        """Return techniques mapped to ``capability_id``."""
        return _TECHNIQUES.get(capability_id, ())

    def missions_for(self, capability_id: str) -> tuple[str, ...]:
        """Return mission profiles mapped to ``capability_id``."""
        return _MISSIONS.get(capability_id, ())

    def classify(self, capability_id: str) -> tuple[str, str]:
        """Return ``(category, subcategory)`` for a capability id.

        Returns ``("", "")`` when the capability is not in the taxonomy.
        """
        for category_id, subcategories in _TAXONOMY.items():
            for subcategory_id, capability_ids in subcategories.items():
                if capability_id in capability_ids:
                    return category_id, subcategory_id
        return "", ""
