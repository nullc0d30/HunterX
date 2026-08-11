# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability knowledge provider adapter registry.

Builds and registers the vulnerability knowledge provider adapters (NVD, CISA
KEV, EPSS, MITRE CWE, vendor advisories, OSV/GHSA) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the provider set, so callers (tests, the knowledge service, the
platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.vuln.base import VulnerabilityProviderAdapter
from hunterx.tools.vuln.injection import (
    CommixAdapter,
    DalfoxAdapter,
    GhauriAdapter,
    InteractshAdapter,
    SQLmapAdapter,
    SSTImapAdapter,
    TplmapAdapter,
    XSStrikeAdapter,
    XXEinjectorAdapter,
)
from hunterx.tools.vuln.nuclei import NucleiAdapter
from hunterx.tools.vuln.providers import (
    AdvisoryAdapter,
    CweAdapter,
    EpssAdapter,
    KevAdapter,
    NvdCveAdapter,
    OsvAdapter,
)
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter

#: Canonical order and set of the integrated knowledge providers.
VULNERABILITY_PROVIDER_IDS: tuple[str, ...] = (
    "nvd-cve",
    "cisa-kev",
    "epss",
    "mitre-cwe",
    "vendor-advisory",
    "osv",
)

#: Canonical order and set of the integrated vulnerability scanners.
VULNERABILITY_SCANNER_IDS: tuple[str, ...] = (
    "nuclei",
    "dalfox",
    "xssstrike",
    "sqlmap",
    "ghauri",
    "commix",
    "tplmap",
    "sstimap",
    "xxeinjector",
    "interactsh",
)


class VulnerabilityProviderFactory:
    """Instantiate the vulnerability knowledge provider adapters."""

    def build(self) -> dict[str, VulnerabilityProviderAdapter]:
        """Return a fresh set of provider adapters keyed by provider id."""
        return {
            "nvd-cve": NvdCveAdapter(),
            "cisa-kev": KevAdapter(),
            "epss": EpssAdapter(),
            "mitre-cwe": CweAdapter(),
            "vendor-advisory": AdvisoryAdapter(),
            "osv": OsvAdapter(),
        }

    def create(self, provider_id: str) -> VulnerabilityProviderAdapter:
        """Return a single adapter instance for ``provider_id``."""
        adapters = self.build()
        if provider_id not in adapters:
            raise KeyError(f"unknown vulnerability knowledge provider '{provider_id}'")
        return adapters[provider_id]


def vulnerability_providers() -> dict[str, VulnerabilityProviderAdapter]:
    """Return a fresh mapping of provider id to adapter instance."""
    return VulnerabilityProviderFactory().build()


def register_vulnerability_providers(
    engine: ExecutionEngine,
) -> Mapping[str, VulnerabilityProviderAdapter]:
    """Register every knowledge provider adapter on ``engine`` and return them."""
    adapters = vulnerability_providers()
    for provider_id, adapter in adapters.items():
        engine.register_adapter(provider_id, adapter)
    return adapters


class VulnerabilityScannerFactory:
    """Instantiate the vulnerability scanner adapters."""

    def build(self) -> dict[str, VulnerabilityScanAdapter]:
        """Return a fresh set of scanner adapters keyed by tool id."""
        return {
            "nuclei": NucleiAdapter(),
            "dalfox": DalfoxAdapter(),
            "xssstrike": XSStrikeAdapter(),
            "sqlmap": SQLmapAdapter(),
            "ghauri": GhauriAdapter(),
            "commix": CommixAdapter(),
            "tplmap": TplmapAdapter(),
            "sstimap": SSTImapAdapter(),
            "xxeinjector": XXEinjectorAdapter(),
            "interactsh": InteractshAdapter(),
        }

    def create(self, tool_id: str) -> VulnerabilityScanAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown vulnerability scanner '{tool_id}'")
        return adapters[tool_id]


def vulnerability_scanners() -> dict[str, VulnerabilityScanAdapter]:
    """Return a fresh mapping of scanner tool id to adapter instance."""
    return VulnerabilityScannerFactory().build()


def register_vulnerability_scanners(
    engine: ExecutionEngine,
) -> Mapping[str, VulnerabilityScanAdapter]:
    """Register every vulnerability scanner adapter on ``engine`` and return them."""
    adapters = vulnerability_scanners()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters


__all__ = [
    "VULNERABILITY_PROVIDER_IDS",
    "VULNERABILITY_SCANNER_IDS",
    "VulnerabilityProviderFactory",
    "VulnerabilityScannerFactory",
    "register_vulnerability_providers",
    "register_vulnerability_scanners",
    "vulnerability_providers",
    "vulnerability_scanners",
]
