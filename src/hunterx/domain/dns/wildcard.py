# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Wildcard DNS detection.

Wildcards answer for any non-existent name in a zone (``*.example.com`` ->
``1.2.3.4``). Failing to detect them makes enumeration hallucinate fake assets;
flagging real records as wildcards would hide genuine infrastructure. This
module detects wildcards deterministically using non-deterministic probing and
labels the affected records so they are never persisted as real assets.
"""

from __future__ import annotations

import ipaddress
import random
import secrets
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, normalize_hostname

#: Answers considered "wildcard evidence" regardless of type.
_EVIDENCE_TYPES = frozenset({DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.CNAME})

#: Hostnames that resolvers may synthesise for non-existent names (RFC 6761).
_SPECIAL_SUFFIXES = (".localhost", ".invalid", ".test", ".example")


@dataclass(frozen=True, slots=True)
class WildcardFinding:
    """The result of probing a zone for wildcard DNS.

    Attributes:
        zone: the zone probed (e.g. ``example.com``).
        wildcard: whether a wildcard answer was detected.
        probed_names: the pseudo-random names that were queried.
        evidence: the record answers captured from the probes.
        signature: canonical answer signature used for matching, when a
            wildcard was detected.
        confidence: detection confidence in ``[0, 1]``.
        details: extra evidence (resolver, timestamps).

    """

    zone: str
    wildcard: bool = False
    probed_names: tuple[str, ...] = ()
    evidence: tuple[DnsRecord, ...] = ()
    signature: str = ""
    confidence: float = 0.0
    details: dict[str, object] = field(default_factory=dict)

    def matching_records(self) -> list[DnsRecord]:
        """Return the evidence records that share the wildcard signature.

        Callers use this to avoid persisting wildcard-poisoned answers as real
        assets.
        """
        if not self.wildcard or not self.signature:
            return []
        return [record for record in self.evidence if _signature(record) == self.signature]


class WildcardDetector:
    """Detect wildcard DNS for a zone.

    The detector queries a handful of pseudo-random names (plus a control query
    for the zone apex) through a resolver callable and compares answer
    signatures. When every random name yields the same signature the zone has a
    wildcard; the evidence set and confidence are captured for reporting.

    The ``resolve`` callable receives a hostname and returns an iterable of
    :class:`DnsRecord` answers.
    """

    def __init__(
        self,
        resolve: Callable[[str], Iterable[DnsRecord]],
        *,
        probes: int = 4,
        apex_probe: bool = True,
        evidence_types: frozenset[DnsRecordType] = _EVIDENCE_TYPES,
    ) -> None:
        if probes < 2:
            raise ValueError("at least two probes are required to detect a wildcard")
        self._resolve = resolve
        self._probes = probes
        self._apex_probe = apex_probe
        self._evidence_types = evidence_types

    def probe(self, zone: str, *, tool_id: str = "", execution_id: str = "", target_id: str | None = None) -> WildcardFinding:
        """Probe ``zone`` and return the wildcard finding."""
        zone = normalize_hostname(zone)
        if _is_special(zone):
            return WildcardFinding(zone=zone)
        names = [f"{_random_label()}.{zone}" for _ in range(self._probes)]
        answers: list[DnsRecord] = []
        for name in names:
            for record in self._resolve(name):
                answers.append(record)
        apex: list[DnsRecord] = []
        if self._apex_probe:
            for record in self._resolve(zone):
                apex.append(record)

        candidate_sigs = {_signature(record) for record in answers if _is_evidence(record, self._evidence_types)}
        apex_sigs = {_signature(record) for record in apex if _is_evidence(record, self._evidence_types)}
        wildcard = len(answers) >= 2 and len(candidate_sigs) == 1 and not (candidate_sigs <= apex_sigs)

        if not wildcard:
            return WildcardFinding(zone=zone, probed_names=tuple(names), evidence=tuple(answers), confidence=0.0)

        signature = next(iter(candidate_sigs))
        confidence = _wildcard_confidence(probes=len(names), answered=len(answers), confirmed=signature not in apex_sigs)
        return WildcardFinding(
            zone=zone,
            wildcard=True,
            probed_names=tuple(names),
            evidence=tuple(answers),
            signature=signature,
            confidence=confidence,
            details={
                "apex": apex_sigs,
                "candidates": sorted(candidate_sigs),
                "resolvers": sorted({r.resolver for r in answers if r.resolver}),
            },
        )


def _signature(record: DnsRecord) -> str:
    """Return the canonical signature of a record's answer."""
    if record.record_type is DnsRecordType.CNAME:
        return f"cname:{normalize_hostname(record.value)}"
    if record.record_type in (DnsRecordType.A, DnsRecordType.AAAA):
        try:
            return f"ip:{ipaddress.ip_address(record.value).compressed}"
        except ValueError:
            return f"ip:{record.value.strip().lower()}"
    return f"{record.record_type.value}:{record.value.strip().lower()}"


def _is_evidence(record: DnsRecord, evidence_types: frozenset[DnsRecordType]) -> bool:
    """Return whether a record counts as wildcard evidence."""
    return record.record_type in evidence_types


def _random_label() -> str:
    """Generate a pseudo-random hostname label that avoids DNS blacklists."""
    return "hx-" + secrets.token_hex(4)


def _is_special(zone: str) -> bool:
    """Return whether a zone is a reserved/special name never worth probing."""
    lowered = zone.lower()
    return any(lowered.endswith(suffix) for suffix in _SPECIAL_SUFFIXES)


def _wildcard_confidence(*, probes: int, answered: int, confirmed: bool) -> float:
    """Deterministic confidence for a wildcard finding.

    Confidence rises with the probe count, drops when not every probe answered
    (partial wildcards), and is boosted when the signature does not match the
    zone apex (strong evidence of a catch-all).
    """
    if answered < 2 or probes < 2:
        return 0.0
    coverage = min(1.0, answered / probes)
    base = 0.8 * coverage
    if confirmed:
        base += 0.15
    return max(0.0, min(1.0, base))


def sample_names(zone: str, count: int = 3) -> list[str]:
    """Return ``count`` pseudo-random subdomains for enumeration probes."""
    return [f"{_random_label()}.{zone}" for _ in range(count)]


def random_choice(sequence: Sequence[object]) -> object:
    """Deterministic random helper (uses ``random`` for reproducibility)."""
    return random.choice(sequence)
