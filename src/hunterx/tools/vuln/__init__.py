# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability tool adapters.

SDK tool adapters for vulnerability knowledge providers (NVD CVE, CISA KEV,
EPSS, MITRE CWE, vendor advisories, OSV/GHSA) and vulnerability scanners
(nuclei). Provider adapters are in-process normalizers that serialize canonical
knowledge under the pipeline payload's ``vulnerabilities`` key; scanner
adapters invoke external binaries and emit canonical *candidate* observations
under the ``candidates`` key, never validated findings.
"""

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
    payload_from_json,
)
from hunterx.tools.vuln.registry import (
    VULNERABILITY_PROVIDER_IDS,
    VULNERABILITY_SCANNER_IDS,
    VulnerabilityProviderFactory,
    VulnerabilityScannerFactory,
    register_vulnerability_providers,
    register_vulnerability_scanners,
    vulnerability_providers,
    vulnerability_scanners,
)
from hunterx.tools.vuln.scanbase import VulnerabilityScanAdapter
from hunterx.tools.vuln.tip import (
    NUCLEI_CONFIDENCE_CEILING,
    register_vulnerability_scanner_tools,
    register_vulnerability_tools,
    vulnerability_scanner_specs,
)

__all__ = [
    "AdvisoryAdapter",
    "CommixAdapter",
    "CweAdapter",
    "DalfoxAdapter",
    "EpssAdapter",
    "GhauriAdapter",
    "InteractshAdapter",
    "KevAdapter",
    "NUCLEI_CONFIDENCE_CEILING",
    "NvdCveAdapter",
    "NucleiAdapter",
    "OsvAdapter",
    "SQLmapAdapter",
    "SSTImapAdapter",
    "TplmapAdapter",
    "VULNERABILITY_PROVIDER_IDS",
    "VULNERABILITY_SCANNER_IDS",
    "VulnerabilityProviderAdapter",
    "VulnerabilityProviderFactory",
    "VulnerabilityScanAdapter",
    "VulnerabilityScannerFactory",
    "XXEinjectorAdapter",
    "XSStrikeAdapter",
    "payload_from_json",
    "register_vulnerability_providers",
    "register_vulnerability_scanner_tools",
    "register_vulnerability_scanners",
    "register_vulnerability_tools",
    "vulnerability_providers",
    "vulnerability_scanner_specs",
    "vulnerability_scanners",
]
