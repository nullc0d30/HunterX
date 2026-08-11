# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS record and resolution validator.

Validates raw DNS output before it is trusted: owner names, rdata values, TTL
bounds, MX/SRV/CAA numeric ranges and response codes. Validation is pure and
non-destructive — invalid observations are marked, never discarded, so the
capability keeps provenance for every answer even when it cannot trust it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, DNSResolution

#: Non-error DNS response codes that can carry answers.
_VALID_RCODES = frozenset({"NOERROR", "NXDOMAIN"})

#: Upper bound on a 32-bit TTL.
_MAX_TTL = 2**31 - 1


@dataclass(frozen=True, slots=True)
class DnsValidationResult:
    """Outcome of validating a DNS record or resolution.

    Attributes:
        valid: whether every check passed.
        issues: human-readable validation messages.
        record_type: the record type validated (for reporting).

    """

    valid: bool
    issues: tuple[str, ...]
    record_type: str = ""

    @property
    def status(self) -> str:
        """Return ``valid`` or ``invalid`` as a string for persistence."""
        return "valid" if self.valid else "invalid"


@dataclass(slots=True)
class DnsValidator:
    """Validate DNS records and resolution outcomes."""

    def validate_record(self, record: DnsRecord) -> DnsValidationResult:
        """Validate one canonical DNS record."""
        issues: list[str] = []
        name = record.name
        if not name:
            issues.append("record owner name is empty")
        elif record.record_type is not DnsRecordType.PTR and not _is_hostname(name):
            issues.append(f"owner name '{name}' is not a valid hostname")
        if record.ttl is not None and not 0 <= record.ttl <= _MAX_TTL:
            issues.append(f"ttl {record.ttl} is out of range [0, {_MAX_TTL}]")
        issues.extend(self._validate_rdata(record))
        return DnsValidationResult(valid=not issues, issues=tuple(issues), record_type=record.record_type.value)

    def validate_resolution(self, resolution: DNSResolution) -> DnsValidationResult:
        """Validate a resolution outcome (response code sanity)."""
        issues: list[str] = []
        if resolution.rcode and resolution.rcode.upper() not in _VALID_RCODES and resolution.status == "resolved":
            issues.append(f"resolution claims success with rcode {resolution.rcode}")
        return DnsValidationResult(valid=not issues, issues=tuple(issues))

    def _validate_rdata(self, record: DnsRecord) -> list[str]:
        """Validate a record's rdata based on its type."""
        value = record.value
        if record.record_type in (DnsRecordType.A, DnsRecordType.AAAA):
            try:
                ip = ipaddress.ip_address(value)
                expected = 4 if record.record_type is DnsRecordType.A else 6
                if ip.version != expected:
                    return [f"{record.record_type.value} record holds an IPv{ip.version} address"]
            except ValueError:
                return [f"{record.record_type.value} record value '{value}' is not an IP address"]
            return []
        if record.record_type in (DnsRecordType.CNAME, DnsRecordType.NS, DnsRecordType.PTR):
            if not _is_hostname(value):
                return [f"{record.record_type.value} record target '{value}' is not a valid hostname"]
            return []
        if record.record_type is DnsRecordType.MX:
            return _validate_mx(record)
        if record.record_type is DnsRecordType.SRV:
            return _validate_srv(record)
        if record.record_type is DnsRecordType.CAA:
            return _validate_caa(record)
        return []


def _is_hostname(value: str) -> bool:
    """Return ``True`` when ``value`` looks like a valid hostname."""
    candidate = value.rstrip(".")
    if len(candidate) > 253 or not candidate:
        return False
    if not re.fullmatch(r"(?i)[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?)*", candidate):
        return False
    return "." in candidate or candidate.isdigit() is False


def _validate_mx(record: DnsRecord) -> list[str]:
    if record.priority is not None and not 0 <= record.priority <= 65535:
        return [f"MX priority {record.priority} is out of range [0, 65535]"]
    if not _is_hostname(record.value):
        return [f"MX exchange '{record.value}' is not a valid hostname"]
    return []


def _validate_srv(record: DnsRecord) -> list[str]:
    parts = record.value.split()
    if len(parts) != 3:
        return [f"SRV rdata '{record.value}' does not have the form 'target port weight'"]
    _target, port, weight = parts
    try:
        if not 0 <= int(port) <= 65535:
            return [f"SRV port {port} is out of range [0, 65535]"]
        if not 0 <= int(weight) <= 65535:
            return [f"SRV weight {weight} is out of range [0, 65535]"]
    except ValueError:
        return [f"SRV rdata '{record.value}' has non-numeric port/weight"]
    if record.priority is not None and not 0 <= record.priority <= 65535:
        return [f"SRV priority {record.priority} is out of range [0, 65535]"]
    return []


def _validate_caa(record: DnsRecord) -> list[str]:
    parts = record.value.split(maxsplit=2)
    if len(parts) < 2:
        return [f"CAA rdata '{record.value}' does not have the form 'flags tag value'"]
    flags = parts[0]
    try:
        if not 0 <= int(flags) <= 255:
            return [f"CAA flags {flags} are out of range [0, 255]"]
    except ValueError:
        return [f"CAA flags '{flags}' is not numeric"]
    return []
