# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS collection strategy.

Maps an execution mode (passive/active/hybrid) and a target kind onto the
concrete set of record types and analyses the capability should run. The
strategy is a pure function of (mode, target, requested features) so the same
inputs always yield the same collection plan.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from hunterx.domain.dns.models import DNSX_QUERYABLE, DnsRecordType
from hunterx.domain.recon.models import ReconMode

#: Record types collected for a bare host target (its own address/name).
_HOST_RECORD_TYPES = frozenset({DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.CNAME, DnsRecordType.PTR})

#: Record types collected for a domain target in active mode.
_ACTIVE_DOMAIN_RECORD_TYPES = frozenset(
    {
        DnsRecordType.A,
        DnsRecordType.AAAA,
        DnsRecordType.CNAME,
        DnsRecordType.MX,
        DnsRecordType.NS,
        DnsRecordType.TXT,
        DnsRecordType.SOA,
        DnsRecordType.PTR,
        DnsRecordType.SRV,
        DnsRecordType.CAA,
        DnsRecordType.DS,
        DnsRecordType.DNSKEY,
        DnsRecordType.TLSA,
        DnsRecordType.NAPTR,
    }
)

#: Record types collected in passive mode (types observable without querying).
_PASSIVE_RECORD_TYPES = frozenset(
    {DnsRecordType.A, DnsRecordType.AAAA, DnsRecordType.CNAME, DnsRecordType.MX, DnsRecordType.NS, DnsRecordType.TXT}
)


@dataclass(frozen=True, slots=True)
class DnsStrategy:
    """A concrete collection plan for a target.

    Attributes:
        target: the target value (domain or host).
        target_kind: ``domain`` or ``host``.
        mode: the execution mode.
        record_types: the record types to collect.
        with_dnssec: whether to collect DNSSEC material.
        with_mail: whether to analyze mail infrastructure.
        with_wildcard: whether to probe for wildcards.
        with_history: whether to compare with historical data.
        active_resolvers: resolver list to use in active mode.
        max_concurrency: resolver concurrency ceiling.

    """

    target: str
    target_kind: str = "domain"
    mode: ReconMode = ReconMode.HYBRID
    record_types: frozenset[DnsRecordType] = field(default_factory=frozenset)
    with_dnssec: bool = False
    with_mail: bool = False
    with_wildcard: bool = False
    with_history: bool = False
    active_resolvers: tuple[str, ...] = ()
    max_concurrency: int = 4


class DnsStrategyBuilder:
    """Build a :class:`DnsStrategy` for a target and mode."""

    def build(
        self,
        target: str,
        *,
        mode: ReconMode = ReconMode.HYBRID,
        target_kind: str = "domain",
        with_dnssec: bool = False,
        with_mail: bool = False,
        with_wildcard: bool = False,
        with_history: bool = False,
        active_resolvers: tuple[str, ...] = (),
        max_concurrency: int = 4,
    ) -> DnsStrategy:
        """Build the strategy for ``target``."""
        if not target_kind:
            target_kind = "host" if _is_ip(target) else "domain"
        record_types = self._record_types_for(mode, target_kind)
        default_resolvers = active_resolvers or _default_resolvers(target)
        return DnsStrategy(
            target=target,
            target_kind=target_kind,
            mode=mode,
            record_types=frozenset(record_types),
            with_dnssec=with_dnssec or mode is ReconMode.ACTIVE or mode is ReconMode.HYBRID,
            with_mail=with_mail or mode is ReconMode.ACTIVE or mode is ReconMode.HYBRID,
            with_wildcard=with_wildcard,
            with_history=with_history,
            active_resolvers=default_resolvers,
            max_concurrency=max_concurrency,
        )

    def record_types_for(self, mode: ReconMode, target_kind: str) -> frozenset[DnsRecordType]:
        """Return the record types the mode/target will collect."""
        return frozenset(self._record_types_for(mode, target_kind))

    def _record_types_for(self, mode: ReconMode, target_kind: str) -> set[DnsRecordType]:
        """Select the record types for a mode and target kind."""
        if target_kind in ("host", "ip"):
            types = set(_HOST_RECORD_TYPES)
        elif mode is ReconMode.PASSIVE:
            types = set(_PASSIVE_RECORD_TYPES)
        else:
            types = set(_ACTIVE_DOMAIN_RECORD_TYPES)
        return types & set(DNSX_QUERYABLE) if types else set(DNSX_QUERYABLE)

    def mode_for(self, policy_value: str) -> ReconMode:
        """Coerce a policy string into a :class:`ReconMode`."""
        try:
            return ReconMode(policy_value.lower())
        except ValueError:
            return ReconMode.HYBRID


def _is_ip(value: str) -> bool:
    """Return whether ``value`` parses as an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _default_resolvers(target: str) -> tuple[str, ...]:
    """Return the default resolver set for a target.

    Public resolvers are only safe to query when the target is a public name;
    for internal/private targets the caller must supply resolvers. This returns
    an empty tuple so the active pipeline fails closed rather than silently
    querying public resolvers for private infrastructure.
    """
    if _is_ip(target):
        return ()
    try:
        ipaddress.ip_address(target)
        return ()
    except ValueError:
        return ("8.8.8.8", "1.1.1.1")
