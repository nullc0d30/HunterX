# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNSSEC intelligence.

Analyzes DNSSEC material (DS, DNSKEY, RRSIG, NSEC/NSEC3) to determine whether
a zone is secured, correctly delegating and protected against forged answers.
Analysis is deterministic: each check is a pure predicate over the collected
records.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.dns.models import DnsRecord, DnsRecordType

#: Statuses a zone can have.
_ZONE_SECURED = "secured"
_ZONE_UNSECURED = "unsecured"
_ZONE_BROKEN = "broken"
_ZONE_INDETERMINATE = "indeterminate"

_ZONE_STATUSES = (_ZONE_SECURED, _ZONE_UNSECURED, _ZONE_BROKEN, _ZONE_INDETERMINATE)

#: Algorithm identifiers that imply a DS but no RRSIGs = broken delegation.
_RRSIG_TYPES = frozenset({DnsRecordType.RRSIG, DnsRecordType.NSEC, DnsRecordType.NSEC3})


@dataclass(frozen=True, slots=True)
class DNSSECFinding:
    """The DNSSEC posture of a zone.

    Attributes:
        zone: the zone analyzed.
        status: one of ``secured``, ``unsecured``, ``broken``,
            ``indeterminate``.
        has_ds: whether a DS record was observed for the zone.
        has_dnskey: whether a DNSKEY record was observed.
        signed: whether RRSIG/NSEC/NSEC3 records were observed.
        checks: per-check results (name -> (passed, detail)).
        confidence: confidence in the finding in ``[0, 1]``.
        details: extra evidence.

    """

    zone: str
    status: str = _ZONE_INDETERMINATE
    has_ds: bool = False
    has_dnskey: bool = False
    signed: bool = False
    checks: dict[str, tuple[bool, str]] = field(default_factory=dict)
    confidence: float = 0.0
    details: dict[str, object] = field(default_factory=dict)

    @property
    def secured(self) -> bool:
        """Return whether the zone is fully DNSSEC secured."""
        return self.status == _ZONE_SECURED


class DnssecAnalyzer:
    """Analyze DNSSEC material for a zone."""

    def __init__(self, minimum_confidence: float = 0.5) -> None:
        self._minimum_confidence = minimum_confidence

    def analyze(self, records: list[DnsRecord]) -> DNSSECFinding:
        """Analyze the DNSSEC posture of a zone from its records.

        ``records`` should be the DNSKEY, DS, RRSIG, NSEC and NSEC3 records
        collected for the zone (answers for the zone apex and its delegation).
        """
        zone = _zone_of(records)
        has_ds = any(_is_type(record, DnsRecordType.DS) for record in records)
        has_dnskey = any(_is_type(record, DnsRecordType.DNSKEY) for record in records)
        signed = any(record.record_type in _RRSIG_TYPES for record in records)
        checks: dict[str, tuple[bool, str]] = {}
        if has_ds and not has_dnskey:
            checks["delegation"] = (False, "DS present but no DNSKEY observed in-zone")
            status = _ZONE_BROKEN
        elif has_ds and has_dnskey and signed:
            checks["material"] = (True, "DS, DNSKEY and RRSIG observed")
            checks["delegation"] = (True, "delegation signed")
            status = _ZONE_SECURED
        elif has_ds and has_dnskey and not signed:
            checks["material"] = (False, "DNSKEY observed without RRSIG/NSEC")
            status = _ZONE_BROKEN
        elif not has_ds and not has_dnskey and not signed:
            checks["delegation"] = (True, "no DNSSEC material; zone is unsigned")
            status = _ZONE_UNSECURED
        else:
            checks["material"] = (False, "partial DNSSEC material; posture indeterminate")
            status = _ZONE_INDETERMINATE

        confidence = _posture_confidence(status, has_ds, has_dnskey, signed)
        return DNSSECFinding(
            zone=zone,
            status=status,
            has_ds=has_ds,
            has_dnskey=has_dnskey,
            signed=signed,
            checks=checks,
            confidence=confidence,
            details={"record_count": len(records)},
        )

    def summary(self, findings: list[DNSSECFinding]) -> dict[str, int]:
        """Summarize a set of findings by status."""
        summary = {status: 0 for status in _ZONE_STATUSES}
        for finding in findings:
            summary[finding.status] = summary.get(finding.status, 0) + 1
        return summary


def _zone_of(records: list[DnsRecord]) -> str:
    """Infer the zone from the first DNSKEY/DS record owner name."""
    for record in records:
        if record.record_type in (DnsRecordType.DNSKEY, DnsRecordType.DS):
            return record.name
    return records[0].name if records else ""


def _is_type(record: DnsRecord, record_type: DnsRecordType) -> bool:
    """Return whether a record has the given type."""
    return record.record_type is record_type


def _posture_confidence(status: str, has_ds: bool, has_dnskey: bool, signed: bool) -> float:
    """Deterministic confidence for a DNSSEC posture."""
    if status == _ZONE_SECURED:
        return 0.95
    if status == _ZONE_UNSECURED:
        return 0.9
    if status == _ZONE_BROKEN:
        return 0.85 if (has_ds and has_dnskey) else 0.6
    return 0.4


def parse_dnskey_flags(value: str) -> tuple[int, int, str]:
    """Parse a DNSKEY rdata into ``(flags, protocol, algorithm)``.

    DNSKEY rdata has the form ``flags protocol algorithm base64key`` (or a
    decimal tuple when the tool rendered it that way).
    """
    parts = value.split()
    if len(parts) >= 4 and parts[0].isdigit() and parts[1].isdigit() and parts[2].isdigit():
        return int(parts[0]), int(parts[1]), parts[2]
    return 256, 3, ""


def _algorithm_name(value: str) -> str:
    """Map a DNSKEY/DS algorithm number to its RFC name (best effort)."""
    names = {"8": "RSASHA256", "13": "ECDSAP256SHA256", "15": "ED25519", "16": "ED448"}
    return names.get(value, f"ALG-{value}")


def algorithm_names(records: list[DnsRecord]) -> list[str]:
    """Return the DNSKEY algorithm names observed in ``records``."""
    names = []
    for record in records:
        if record.record_type is DnsRecordType.DNSKEY:
            _, _, algorithm = parse_dnskey_flags(record.value)
            name = _algorithm_name(algorithm)
            if name not in names:
                names.append(name)
    return sorted(names)
