# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Vulnerability knowledge provider adapters.

In-process adapters that normalize external vulnerability-knowledge payloads
(NVD CVE JSON, CISA KEV catalog, EPSS score files, MITRE CWE data, vendor
advisories, GHSA/OSV records, SBOM documents) into the canonical
:class:`~hunterx.domain.vulnerability.models.Vulnerability` /
:class:`~hunterx.domain.vulnerability.models.VulnerabilityKnowledgeBatch`
contract. These adapters perform data normalization only — they never contact
the provider at runtime, never fetch remote content and never execute anything.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.vulnerability.enums import KnowledgeSourceKind
from hunterx.domain.vulnerability.models import (
    VulnerabilityKnowledgeBatch,
)
from hunterx.domain.vulnerability.normalizer import VulnerabilityNormalizer
from hunterx.tools.vuln.base import VulnerabilityProviderAdapter


class NvdCveAdapter(VulnerabilityProviderAdapter):
    """Normalize NVD CVE feed/API payloads into canonical vulnerabilities."""

    descriptor = ToolDescriptor(
        name="nvd-cve",
        version="1.0.0",
        description=(
            "In-process NVD CVE normalization: NVD 2.0 CVE_Items and API "
            "vulnerabilities payloads are normalized to the canonical "
            "vulnerability model. Intelligence only; never performs "
            "vulnerability validation."
        ),
        entrypoint="hunterx.tools.vuln.providers:NvdCveAdapter",
        targets=("knowledge",),
        capabilities=("vulnerability-knowledge", "cve-intelligence", "nvd"),
        permissions=("none",),
        parameters={
            "raw": {"type": "object", "description": "NVD CVE payload (CVE_Items or vulnerabilities[])."},
            "source": {"type": "string", "description": "Source label for provenance."},
        },
    )

    provider_kind = KnowledgeSourceKind.NVD

    def __init__(self, *, normalizer: VulnerabilityNormalizer | None = None) -> None:
        self._normalizer = normalizer or VulnerabilityNormalizer()

    def ingest(self, raw: Any, *, source: str = "nvd") -> VulnerabilityKnowledgeBatch:
        """Normalize an NVD CVE payload into canonical vulnerabilities."""
        batch = VulnerabilityKnowledgeBatch(correlation_id=source)
        for record in _cve_records(raw):
            normalized = self._normalizer.normalize_cve(record, source=source)
            if normalized is not None:
                batch.add_vulnerability(normalized)
        return batch


class KevAdapter(VulnerabilityProviderAdapter):
    """Normalize CISA Known Exploited Vulnerabilities catalog entries."""

    descriptor = ToolDescriptor(
        name="cisa-kev",
        version="1.0.0",
        description=(
            "In-process CISA KEV normalization: catalog entries are normalized "
            "to canonical KEV records. Metadata only; HunterX never exploits "
            "KEV entries."
        ),
        entrypoint="hunterx.tools.vuln.providers:KevAdapter",
        targets=("knowledge",),
        capabilities=("vulnerability-knowledge", "kev-intelligence", "cisa-kev"),
        permissions=("none",),
        parameters={
            "raw": {"type": "object", "description": "CISA KEV catalog payload."},
            "source": {"type": "string", "description": "Source label for provenance."},
        },
    )

    provider_kind = KnowledgeSourceKind.CISA_KEV

    def __init__(self, *, normalizer: VulnerabilityNormalizer | None = None) -> None:
        self._normalizer = normalizer or VulnerabilityNormalizer()

    def ingest(self, raw: Any, *, source: str = "cisa-kev") -> VulnerabilityKnowledgeBatch:
        """Normalize a CISA KEV catalog payload into canonical KEV records."""
        batch = VulnerabilityKnowledgeBatch(correlation_id=source)
        for record in _kev_records(raw):
            normalized = self._normalizer.normalize_kev(record, source=source)
            if normalized is not None:
                batch.add_kev(normalized)
        return batch


class EpssAdapter(VulnerabilityProviderAdapter):
    """Normalize EPSS score data (CSV rows or JSON entries)."""

    descriptor = ToolDescriptor(
        name="epss",
        version="1.0.0",
        description=(
            "In-process EPSS normalization: first.org EPSS score rows (CSV or "
            "JSON) are normalized to canonical EPSS records. EPSS is a risk "
            "signal only."
        ),
        entrypoint="hunterx.tools.vuln.providers:EpssAdapter",
        targets=("knowledge",),
        capabilities=("vulnerability-knowledge", "epss-intelligence", "epss"),
        permissions=("none",),
        parameters={
            "raw": {"type": "object", "description": "EPSS score payload (CSV text or JSON list)."},
            "source": {"type": "string", "description": "Source label for provenance."},
        },
    )

    provider_kind = KnowledgeSourceKind.EPSS

    def __init__(self, *, normalizer: VulnerabilityNormalizer | None = None) -> None:
        self._normalizer = normalizer or VulnerabilityNormalizer()

    def ingest(self, raw: Any, *, source: str = "first.org") -> VulnerabilityKnowledgeBatch:
        """Normalize an EPSS score payload into canonical EPSS records."""
        batch = VulnerabilityKnowledgeBatch(correlation_id=source)
        for record in _epss_records(raw):
            normalized = self._normalizer.normalize_epss(record, source=source)
            if normalized is not None:
                batch.add_epss(normalized)
        return batch


class CweAdapter(VulnerabilityProviderAdapter):
    """Normalize MITRE CWE data into canonical CWE entries."""

    descriptor = ToolDescriptor(
        name="mitre-cwe",
        version="1.0.0",
        description=(
            "In-process MITRE CWE normalization: CWE weakness records are "
            "normalized to the canonical CWE model with hierarchy relations."
        ),
        entrypoint="hunterx.tools.vuln.providers:CweAdapter",
        targets=("knowledge",),
        capabilities=("vulnerability-knowledge", "cwe-intelligence", "mitre-cwe"),
        permissions=("none",),
        parameters={
            "raw": {"type": "object", "description": "MITRE CWE payload."},
            "source": {"type": "string", "description": "Source label for provenance."},
        },
    )

    provider_kind = KnowledgeSourceKind.MITRE_CWE

    def __init__(self, *, normalizer: VulnerabilityNormalizer | None = None) -> None:
        self._normalizer = normalizer or VulnerabilityNormalizer()

    def ingest(self, raw: Any, *, source: str = "mitre-cwe") -> VulnerabilityKnowledgeBatch:
        """Normalize a MITRE CWE payload into canonical CWE entries."""
        batch = VulnerabilityKnowledgeBatch(correlation_id=source)
        for record in _cwe_records(raw):
            normalized = self._normalizer.normalize_cwe(record, source=source)
            if normalized is not None:
                batch.add_cwe(normalized)
        return batch


class AdvisoryAdapter(VulnerabilityProviderAdapter):
    """Normalize vendor security advisories."""

    descriptor = ToolDescriptor(
        name="vendor-advisory",
        version="1.0.0",
        description=(
            "In-process vendor-advisory normalization: vendor security "
            "advisories are normalized to the canonical advisory model."
        ),
        entrypoint="hunterx.tools.vuln.providers:AdvisoryAdapter",
        targets=("knowledge",),
        capabilities=("vulnerability-knowledge", "advisory-intelligence", "vendor-advisory"),
        permissions=("none",),
        parameters={
            "raw": {"type": "object", "description": "Vendor advisory payload."},
            "source": {"type": "string", "description": "Source label for provenance."},
        },
    )

    provider_kind = KnowledgeSourceKind.VENDOR_ADVISORY

    def __init__(self, *, normalizer: VulnerabilityNormalizer | None = None) -> None:
        self._normalizer = normalizer or VulnerabilityNormalizer()

    def ingest(self, raw: Any, *, source: str = "vendor-advisory") -> VulnerabilityKnowledgeBatch:
        """Normalize a vendor advisory payload into canonical advisories."""
        batch = VulnerabilityKnowledgeBatch(correlation_id=source)
        for record in _advisory_records(raw):
            normalized = self._normalizer.normalize_advisory(record, source=source)
            if normalized is not None:
                batch.add_advisory(normalized)
        return batch


class OsvAdapter(VulnerabilityProviderAdapter):
    """Normalize OSV/GHSA advisory records."""

    descriptor = ToolDescriptor(
        name="osv",
        version="1.0.0",
        description=(
            "In-process OSV/GHSA normalization: OSV-style advisory records are "
            "normalized to canonical vulnerabilities."
        ),
        entrypoint="hunterx.tools.vuln.providers:OsvAdapter",
        targets=("knowledge",),
        capabilities=("vulnerability-knowledge", "osv-intelligence", "ghsa", "osv"),
        permissions=("none",),
        parameters={
            "raw": {"type": "object", "description": "OSV advisory payload."},
            "source": {"type": "string", "description": "Source label for provenance."},
        },
    )

    provider_kind = KnowledgeSourceKind.OSV

    def __init__(self, *, normalizer: VulnerabilityNormalizer | None = None) -> None:
        self._normalizer = normalizer or VulnerabilityNormalizer()

    def ingest(self, raw: Any, *, source: str = "osv") -> VulnerabilityKnowledgeBatch:
        """Normalize an OSV/GHSA advisory payload into canonical vulnerabilities."""
        batch = VulnerabilityKnowledgeBatch(correlation_id=source)
        for record in _osv_records(raw):
            normalized = self._normalizer.normalize_osv(record, source=source)
            if normalized is not None:
                batch.add_vulnerability(normalized)
        return batch


# -- raw record extraction helpers -------------------------------------------


def _cve_records(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, dict):
        return []
    if isinstance(raw.get("vulnerabilities"), list):
        return [item for item in raw["vulnerabilities"] if isinstance(item, dict)]
    if isinstance(raw.get("CVE_Items"), list):
        return [item for item in raw["CVE_Items"] if isinstance(item, dict)]
    if raw.get("id") or raw.get("cve_id"):
        return [raw]
    return []


def _kev_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        if isinstance(raw.get("vulnerabilities"), list):
            return [item for item in raw["vulnerabilities"] if isinstance(item, dict)]
        if raw.get("cveID") or raw.get("cve_id"):
            return [raw]
    return []


def _epss_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        if isinstance(raw.get("scores"), list):
            return [item for item in raw["scores"] if isinstance(item, dict)]
        if raw.get("cve") or raw.get("cve_id"):
            return [raw]
    if isinstance(raw, str):
        return _epss_csv_rows(raw)
    return []


def _epss_csv_rows(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            if not isinstance(row, dict):
                continue
            rows.append(row)
    except csv.Error:
        return []
    return rows


def _cwe_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        if isinstance(raw.get("weaknesses"), list):
            return [item for item in raw["weaknesses"] if isinstance(item, dict)]
        if raw.get("id") or raw.get("cwe_id"):
            return [raw]
    return []


def _advisory_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        if isinstance(raw.get("advisories"), list):
            return [item for item in raw["advisories"] if isinstance(item, dict)]
        if raw.get("advisory_id") or raw.get("id"):
            return [raw]
    return []


def _osv_records(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        if isinstance(raw.get("vulns"), list):
            return [item for item in raw["vulns"] if isinstance(item, dict)]
        if raw.get("id") or raw.get("osv_id"):
            return [raw]
    return []


def payload_from_json(text: str) -> Any:
    """Parse a provider JSON payload defensively."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


__all__ = [
    "AdvisoryAdapter",
    "CweAdapter",
    "EpssAdapter",
    "KevAdapter",
    "NvdCveAdapter",
    "OsvAdapter",
    "payload_from_json",
]
