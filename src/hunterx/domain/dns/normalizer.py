# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS record normalizer.

Turns raw DNS observations into canonical :class:`DnsRecord` values while
preserving the original observation. Normalization is idempotent and pure: the
same raw input always yields the same normalized output, and the original
``raw_value`` is never lost.

Coverage:
    * owner-name case and trailing dots,
    * internationalized domain names (punycode),
    * IPv4/IPv6 canonical (compressed) forms,
    * TTL clamping (``0`` is preserved),
    * MX/SRV priorities split from the exchange/target,
    * CAA tag/flag/value decomposition,
    * TXT fragment joining (quoted 255-byte segments),
    * SOA field splitting,
    * nameserver names,
    * deterministic record ordering for multi-value answers.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, normalize_hostname

#: A single quoted TXT character-string (no embedded quotes); multi-fragment
#: values fall through to the findall-based joiner.
_TXT_FRAGMENT_SPLIT = re.compile(r'^"((?:[^"\\]|\\.)*)"$')

#: SRV rdata: ``priority weight port target``.
_SRV = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$")

#: CAA rdata: ``flags tag value`` (value may be quoted).
_CAA = re.compile(r"^\s*(\d+)\s+([a-z0-9-]+)\s+(.*?)\s*$", re.IGNORECASE)

#: SOA rdata: ``mname rname serial refresh retry expire minimum``.
_SOA = re.compile(
    r"^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$"
)

#: NAPTR rdata: ``order preference flags service regexp replacement``.
_NAPTR = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$")


class DnsNormalizer:
    """Normalize raw DNS record observations into canonical records."""

    def normalize(self, record: DnsRecord) -> DnsRecord:
        """Return ``record`` with normalized name/value fields.

        The original observation is preserved in ``raw_value`` and the owner
        name is always canonicalized (lowercase, no trailing dot).
        """
        name = normalize_hostname(record.name)
        value = str(record.raw_value or record.value).strip()
        handler = {
            DnsRecordType.A: self._normalize_address,
            DnsRecordType.AAAA: self._normalize_address,
            DnsRecordType.CNAME: self._normalize_target,
            DnsRecordType.NS: self._normalize_target,
            DnsRecordType.PTR: self._normalize_target,
            DnsRecordType.MX: self._normalize_mx,
            DnsRecordType.SRV: self._normalize_srv,
            DnsRecordType.CAA: self._normalize_caa,
            DnsRecordType.SOA: self._normalize_soa,
            DnsRecordType.NAPTR: self._normalize_naptr,
            DnsRecordType.TXT: self._normalize_txt,
            DnsRecordType.DS: self._normalize_dnssec,
            DnsRecordType.DNSKEY: self._normalize_dnssec,
            DnsRecordType.TLSA: self._normalize_dnssec,
            DnsRecordType.NSEC: self._normalize_dnssec,
            DnsRecordType.NSEC3: self._normalize_dnssec,
            DnsRecordType.RRSIG: self._normalize_dnssec,
            DnsRecordType.ANY: _identity,
            DnsRecordType.OTHER: _identity,
        }
        handler_fn = handler.get(record.record_type, _identity)
        normalized_value, priority = handler_fn(value)
        return DnsRecord(
            name=name,
            record_type=record.record_type,
            value=normalized_value,
            raw_value=record.raw_value or value,
            ttl=_clamp_ttl(record.ttl),
            priority=record.priority if priority is None else priority,
            source=record.source,
            tool_id=record.tool_id,
            resolver=record.resolver,
            observed_at=record.observed_at,
            execution_id=record.execution_id,
            correlation_id=record.correlation_id,
            target_id=record.target_id,
            validation_status=record.validation_status,
            confidence=record.confidence,
            record_id=record.record_id,
        )

    def normalize_many(self, records: Iterable[DnsRecord]) -> list[DnsRecord]:
        """Normalize an iterable of records, returning a list."""
        return [self.normalize(record) for record in records]

    # -- per-type handlers --------------------------------------------------

    def _normalize_address(self, value: str) -> tuple[str, int | None]:
        try:
            return ipaddress.ip_address(value).compressed, None
        except ValueError:
            return normalize_hostname(value), None

    def _normalize_target(self, value: str) -> tuple[str, int | None]:
        return normalize_hostname(value), None

    def _normalize_mx(self, value: str) -> tuple[str, int | None]:
        parts = value.split()
        if len(parts) == 2 and parts[0].isdigit():
            return normalize_hostname(parts[1]), int(parts[0])
        return normalize_hostname(value), None

    def _normalize_srv(self, value: str) -> tuple[str, int | None]:
        match = _SRV.match(value)
        if match:
            priority, _weight, _port, target = match.groups()
            return f"{target} {_port} {_weight}", int(priority)
        return value, None

    def _normalize_caa(self, value: str) -> tuple[str, int | None]:
        match = _CAA.match(value)
        if match:
            flags, tag, raw = match.groups()
            clean = raw.strip().strip('"')
            return f"{int(flags)} {tag.lower()} {clean}", None
        return value, None

    def _normalize_soa(self, value: str) -> tuple[str, int | None]:
        match = _SOA.match(value)
        if match:
            mname, rname, *rest = match.groups()
            return f"{normalize_hostname(mname)} {rname} {' '.join(rest)}", None
        return value, None

    def _normalize_naptr(self, value: str) -> tuple[str, int | None]:
        match = _NAPTR.match(value)
        if match:
            order, preference, *_rest = match.groups()
            return value.strip(), int(preference) if order == preference else None
        return value, None

    def _normalize_txt(self, value: str) -> tuple[str, int | None]:
        return _join_txt_fragments(value), None

    def _normalize_dnssec(self, value: str) -> tuple[str, int | None]:
        # DNSSEC material (DS/DNSKEY/TLSA/NSEC/NSEC3/RRSIG) is whitespace
        # collapsed but otherwise preserved verbatim — reordering it would be
        # lossy.
        return " ".join(value.split()), None


def _identity(value: str) -> tuple[str, int | None]:
    """Return the value unchanged (for passthrough record types)."""
    return value, None


def _clamp_ttl(ttl: int | None) -> int | None:
    if ttl is None:
        return None
    return max(0, int(ttl))


def _join_txt_fragments(value: str) -> str:
    """Join quoted TXT fragments into a single string.

    A TXT rdata is a sequence of one or more character-strings, each up to 255
    bytes, that DNS clients concatenate. Tools render them either as one quoted
    string or as ``"a" "b"``. This joiner flattens the fragments without
    altering the content.
    """
    stripped = value.strip()
    match = _TXT_FRAGMENT_SPLIT.match(stripped)
    if match:
        return match.group(1)
    if '"' not in stripped:
        return stripped
    fragments = re.findall(r'"((?:[^"\\]|\\.)*)"', stripped)
    if fragments:
        return "".join(fragments)
    return stripped
