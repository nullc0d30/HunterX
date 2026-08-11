# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Active DNS resolver client and pool.

Resolves names through a pool of resolvers using ``dnspython`` with per-query
timeouts, retries, deduplication and TTL-aware caching. The client is the
active-mode workhorse of the DNS capability: it queries each record type for a
target, normalizes answers into canonical :class:`DnsRecord` instances and
treats resolver output as untrusted input (never executes, never parses
beyond structured answers).

Caching uses the shared :class:`~hunterx.domain.ports.messaging.CachePort`
abstraction with target-scoped cache keys so no parallel cache framework is
introduced.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from hunterx.domain.dns.models import DnsRecord, DnsRecordType, make_record
from hunterx.domain.ports.messaging import CachePort
from hunterx.shared.time import utcnow_iso


class ResolverClient:
    """Resolve names through one or more resolvers with caching.

    Usage::

        client = ResolverClient(resolvers=["1.1.1.1", "8.8.8.8"], timeout_s=3)
        records = client.resolve_type("example.com", DnsRecordType.A, tool_id="dnspython")
    """

    def __init__(
        self,
        *,
        resolvers: Sequence[str] = (),
        timeout_s: int = 3,
        lifetime_s: int = 8,
        retries: int = 1,
        cache: CachePort | None = None,
        cache_ttl: int = 300,
    ) -> None:
        self._resolvers = tuple(resolvers)
        self._timeout_s = timeout_s
        self._lifetime_s = lifetime_s
        self._retries = retries
        self._cache = cache
        self._cache_ttl = cache_ttl
        self.resolve = self._default_resolve

    @property
    def resolvers(self) -> tuple[str, ...]:
        """Return the configured resolver addresses."""
        return self._resolvers

    def resolve_type(self, name: str, record_type: DnsRecordType, *, tool_id: str = "") -> list[DnsRecord]:
        """Resolve ``record_type`` answers for ``name``.

        Answers are cached keyed by ``dns:<target>:<type>`` when a cache is
        configured. Each answer is stamped with the resolver that produced it.
        """
        cache_key = self._cache_key(name, record_type)
        if self._cache is not None:
            cached = self._cache.get(cache_key)
            if isinstance(cached, list):
                return list(cached)
        answers = self._query_with_retry(name, record_type, tool_id=tool_id)
        if self._cache is not None and answers:
            self._cache.set(cache_key, answers, ttl_seconds=self._cache_ttl)
        return answers

    def resolve_names(self, names: Sequence[str], record_type: DnsRecordType, *, tool_id: str = "") -> list[DnsRecord]:
        """Resolve one record type across many names, deduplicating answers."""
        seen: set[str] = set()
        records: list[DnsRecord] = []
        for name in names:
            for record in self.resolve_type(name, record_type, tool_id=tool_id):
                key = record.key()
                if key in seen:
                    continue
                seen.add(key)
                records.append(record)
        return records

    def _query_with_retry(self, name: str, record_type: DnsRecordType, *, tool_id: str) -> list[DnsRecord]:
        """Query resolvers, retrying on timeout/failure up to ``retries``."""
        attempts = max(1, self._retries + 1)
        for attempt in range(attempts):
            try:
                answers = self._query_all(name, record_type, tool_id=tool_id)
                if answers:
                    return answers
            except Exception:  # noqa: BLE001 - resolver failures are transient
                if attempt == attempts - 1:
                    raise
        return []

    def _query_all(self, name: str, record_type: DnsRecordType, *, tool_id: str) -> list[DnsRecord]:
        """Query each resolver and merge the answers into canonical records."""
        resolvers = self._resolvers or ()
        records: list[DnsRecord] = []
        for resolver in resolvers:
            records.extend(self._resolve_through(resolver, name, record_type, tool_id=tool_id))
        if not resolvers:
            records.extend(self._resolve_through("", name, record_type, tool_id=tool_id))
        return records

    def _default_resolve(self, name: str, record_type: DnsRecordType, *, resolver: str = "", tool_id: str = "") -> list[DnsRecord]:
        """Resolve through dnspython; returns canonical records or empty list."""
        try:
            import dns.resolver as _dns_resolver
        except ImportError as exc:  # pragma: no cover - guarded runtime dependency
            raise RuntimeError("dnspython is required for active DNS resolution") from exc

        if resolver:
            try:
                import dns.resolver as _resolver_module

                custom = _resolver_module.Resolver(configure=False)
                custom.nameservers = [resolver]
                custom.timeout = self._timeout_s
                custom.lifetime = self._lifetime_s
                answers = custom.resolve(name, _record_type_name(record_type), lifetime=self._lifetime_s)
            except Exception:  # noqa: BLE001 - propagate as empty on any resolver error
                return []
        else:
            answers = _dns_resolver.resolve(name, _record_type_name(record_type), lifetime=self._lifetime_s)
        return _answers_to_records(name, record_type, answers, resolver=resolver, tool_id=tool_id)

    def _resolve_through(self, resolver: str, name: str, record_type: DnsRecordType, *, tool_id: str) -> list[DnsRecord]:
        """Wrap a single resolver query in error isolation."""
        try:
            return list(self.resolve(name, record_type, resolver=resolver, tool_id=tool_id))
        except Exception:  # noqa: BLE001 - one resolver failing never fails the pool
            return []

    def _cache_key(self, name: str, record_type: DnsRecordType) -> str:
        """Return the target-scoped cache key for a query."""
        target = name.strip().lower().rstrip(".")
        return f"dns:{target}:{record_type.value}"


def _record_type_name(record_type: DnsRecordType) -> str:
    """Map a canonical record type to the dnspython query name."""
    return record_type.value


def _answers_to_records(
    name: str,
    record_type: DnsRecordType,
    answers: Iterable[object],
    *,
    resolver: str,
    tool_id: str,
) -> list[DnsRecord]:
    """Project dnspython answers into canonical records."""
    records: list[DnsRecord] = []
    observed_at = utcnow_iso()
    for answer in answers:
        ttl = int(getattr(answer, "ttl", None) or 0)
        value = _answer_value(answer, record_type)
        if value is None:
            continue
        records.append(
            make_record(
                name,
                record_type,
                value,
                ttl=ttl or None,
                source=resolver or "dnspython",
                tool_id=tool_id or "dnspython",
                resolver=resolver,
                observed_at=observed_at,
            )
        )
    return records


def _answer_value(answer: Any, record_type: DnsRecordType) -> str | None:
    """Render one dnspython answer into a canonical string value."""
    try:
        if record_type is DnsRecordType.MX:
            return f"{answer.preference} {answer.exchange}"
        if record_type is DnsRecordType.SRV:
            return f"{answer.priority} {answer.weight} {answer.port} {answer.target}"
        if record_type is DnsRecordType.CAA:
            return f"{answer.flags} {answer.tag} {answer.value}"
        if record_type is DnsRecordType.TXT:
            return "".join(chunk.decode() if isinstance(chunk, bytes) else str(chunk) for chunk in answer.strings)
        if record_type is DnsRecordType.NAPTR:
            return f"{answer.order} {answer.preference} {answer.flags} {answer.service} {answer.regexp} {answer.replacement}"
        return str(answer)
    except Exception:  # noqa: BLE001 - malformed answers must not abort the pool
        return None
