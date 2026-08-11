# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Canonical capability vocabulary (Sprint 031).

HunterX must speak ONE capability language across the toolchain. Different
layers historically used different vocabularies: the TIP taxonomy says
``subdomain-discovery`` while the mastery arsenal says ``subdomain-enumeration``.
This module canonicalizes arsenal capability ids to the canonical taxonomy so
selection, recommendation, chaining and correlation stay consistent.
"""

from __future__ import annotations

#: Arsenal capability id → canonical taxonomy capability id.
#: Entries absent from this map are already canonical.
CAPABILITY_ALIASES: dict[str, str] = {
    # -- recon -------------------------------------------------------------
    "subdomain-enumeration": "subdomain-discovery",
    "domain-enumeration": "subdomain-discovery",
    "dns-enumeration": "dns-records",
    "port-discovery": "port-scanning",
    "host-discovery": "host-discovery",
    "asn-enumeration": "host-discovery",
    "osint": "host-discovery",
    "asset-discovery": "host-discovery",
    # -- dns ----------------------------------------------------------------
    "dns-resolution": "dns-records",
    "brute-force-dns": "dns-records",
    "record-enumeration": "dns-records",
    "wildcard-detection": "dns-records",
    # -- services / tech ----------------------------------------------------
    "service-discovery": "service-fingerprint",
    "os-detection": "service-fingerprint",
    "version-detection": "service-fingerprint",
    "tls-analysis": "ssl-analysis",
    "waf-detection": "technology-detection",
    "web-server-analysis": "technology-detection",
    "http-probing": "http-enumeration",
    "http-configuration-analysis": "http-enumeration",
    "vhost-enumeration": "http-enumeration",
    # -- crawling / discovery ------------------------------------------------
    "crawling": "web-crawling",
    "url-discovery": "web-crawling",
    "historical-url-discovery": "web-crawling",
    "directory-enumeration": "directory-discovery",
    "file-enumeration": "directory-discovery",
    "content-discovery": "directory-discovery",
    "content-discovery-aid": "directory-discovery",
    "dns-bruteforce-aid": "dns-records",
    # -- parameters ----------------------------------------------------------
    "get-parameter-discovery": "parameter-discovery",
    "post-parameter-discovery": "parameter-discovery",
    "historical-parameter-discovery": "parameter-discovery",
    "api-parameter-analysis": "api-fuzzing",
    "query-analysis": "api-fuzzing",
    "openapi-analysis": "api-discovery",
    # -- graphql --------------------------------------------------------------
    "graphql-introspection": "graphql-testing",
    "graphql-analysis": "graphql-testing",
    # -- javascript -----------------------------------------------------------
    "javascript-discovery": "javascript-analysis",
    "endpoint-discovery": "javascript-analysis",
    "endpoint-extraction": "javascript-analysis",
    "source-map-discovery": "javascript-analysis",
    "dom-analysis": "javascript-analysis",
    "secret-indicator-discovery": "secrets-detection",
    # -- vulnerability --------------------------------------------------------
    "web-vulnerability-detection": "vulnerability-scan",
    "network-vulnerability-detection": "vulnerability-scan",
    "misconfiguration-detection": "misconfiguration",
    "vulnerability-pattern-detection": "vulnerability-scan",
    "exposure-detection": "vulnerability-scan",
    "cve-analysis": "cve-detection",
    "cve-research": "cve-detection",
    "version-mapping": "cve-detection",
    "vulnerability-mapping": "cve-detection",
    # -- injection -------------------------------------------------------------
    "sql-injection-detection": "sqli-detection",
    "sql-injection-validation": "sqli-detection",
    "database-fingerprinting": "sqli-detection",
    "xss-discovery": "xss-detection",
    "xss-validation": "xss-detection",
    "reflection-analysis": "xss-detection",
    "parameter-analysis": "xss-detection",
    "ssti-validation": "ssti-detection",
    "template-engine-identification": "ssti-detection",
    "xxe-validation": "xxe-detection",
    "command-injection-detection": "command-injection",
    "command-injection-validation": "command-injection",
    "oob-callback": "oob-testing",
    "interaction-correlation": "oob-testing",
    "oob-xml-interaction": "oob-testing",
    "dns-callback": "oob-testing",
    "http-callback": "oob-testing",
    "smtp-callback": "oob-testing",
    # -- secrets ----------------------------------------------------------------
    "secret-discovery": "secrets-detection",
    "credential-discovery": "secrets-detection",
    "key-discovery": "secrets-detection",
    "token-discovery": "token-analysis",
    # -- SAST --------------------------------------------------------------------
    "code-pattern-analysis": "static-analysis",
    "code-flow-analysis": "static-analysis",
    "taint-analysis": "static-analysis",
    # -- proxy -------------------------------------------------------------------
    "http-interception": "proxy-inspection",
    "traffic-capture": "proxy-inspection",
    "request-replay": "proxy-inspection",
    "response-analysis": "proxy-inspection",
    # -- exploit ------------------------------------------------------------------
    "exploit-research": "exploit-development",
    "exploit-intelligence": "exploit-development",
    "exploit-validation": "exploit-development",
    "payload-capability": "exploit-development",
    "payload-generation": "exploit-development",
    "payload-intelligence": "exploit-development",
    "vulnerability-class-payloads": "exploit-development",
    "session-management": "exploit-development",
    "impact-statement": "evidence-capture",
    # -- cloud / container -----------------------------------------------------------
    "cloud-asset-discovery": "cloud-assessment",
    "cloud-misconfiguration": "cloud-assessment",
    "cloud-permission-audit": "cloud-permission-audit",
    "container-analysis": "container-assessment",
    "container-assessment": "container-assessment",
    "k8s-configuration-analysis": "k8s-audit",
    "kubernetes-security": "k8s-audit",
    "sbom": "image-scan",
    "sbom-generation": "image-scan",
    "dependency-analysis": "image-scan",
    # -- enterprise -------------------------------------------------------------------
    "active-directory-intelligence": "active-directory",
    "kerberos-enumeration": "kerberos-attacks",
    "network-device-enumeration": "active-directory",
    "windows-enumeration": "active-directory",
    "smb-enumeration": "active-directory",
    "snmp-enumeration": "active-directory",
    "password-audit-aid": "identity-enumeration",
    "password-cracking": "identity-enumeration",
    "hash-analysis": "identity-enumeration",
    "hash-modes": "identity-enumeration",
    # -- knowledge / payload / wordlists -----------------------------------------------
    "wordlist-generation": "web-crawling",
    "custom-wordlists": "web-crawling",
    "wordlist-provider": "reporting",
    "attack-patterns": "web-fuzzing",
    "response-patterns": "web-fuzzing",
    "discovery-dictionaries": "web-fuzzing",
    "safe-validation": "web-fuzzing",
    "proof-replay": "evidence-capture",
    # -- misc ---------------------------------------------------------------------------
    "authentication-analysis": "token-analysis",
    "jwt-analysis": "token-analysis",
    "active-testing": "vulnerability-scan",
}


class CapabilityVocabulary:
    """Canonicalize capability ids across the toolchain.

    Usage::

        vocabulary = CapabilityVocabulary()
        vocabulary.canonical("subdomain-enumeration")   # "subdomain-discovery"
        vocabulary.is_known("port-scanning")            # True
        vocabulary.variants("subdomain-discovery")      # ["subdomain-enumeration", ...]
    """

    def __init__(self) -> None:
        self._aliases = dict(CAPABILITY_ALIASES)
        self._reverse: dict[str, list[str]] = {}
        for variant, canonical in self._aliases.items():
            self._reverse.setdefault(canonical, []).append(variant)

    def canonical(self, capability_id: str) -> str:
        """Return the canonical form of ``capability_id``."""
        return self._aliases.get(capability_id, capability_id)

    def is_known(self, capability_id: str) -> bool:
        """Return ``True`` when the id is canonical or an alias."""
        return capability_id in self._aliases or capability_id in self._reverse

    def variants(self, canonical_id: str) -> tuple[str, ...]:
        """Return the alias variants known for ``canonical_id``."""
        return tuple(self._reverse.get(canonical_id, ()))

    def known_ids(self) -> tuple[str, ...]:
        """Return every capability id the vocabulary understands."""
        ids = set(self._aliases)
        ids.update(self._reverse)
        return tuple(sorted(ids))

    def canonical_ids(self) -> tuple[str, ...]:
        """Return every canonical capability id."""
        ids = set(self._reverse) | {
            alias for alias in self._aliases.values() if alias not in self._aliases and alias not in self._reverse
        }
        return tuple(sorted(ids))


__all__ = ["CAPABILITY_ALIASES", "CapabilityVocabulary"]
