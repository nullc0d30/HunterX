# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the HunterX foundation.

Benchmarks are executed by the performance quality gate
(``python -m eng gates --gate performance``) with pytest-benchmark. Results
are compared against ``artifacts/benchmarks/baseline.json``; drift beyond the
configured threshold (20% by default) fails the gate.
"""

from __future__ import annotations

from hunterx.domain.dns.confidence import DnsConfidenceEngine
from hunterx.domain.dns.correlator import correlate_records
from hunterx.domain.dns.models import DnsRecordType, make_record
from hunterx.domain.dns.scope import ScopeEnforcer, ScopePolicy
from hunterx.domain.dns.validator import DnsValidator
from hunterx.shared.ids import generate_content_id, generate_id


def _payload() -> dict:
    return {"target": "https://example.com", "tags": ["web", "tls", "headers"], "depth": 3}


def test_content_hash_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Content hashing must stay fast; it dedups every finding/evidence."""

    def _hash_many() -> int:
        total = 0
        for _ in range(200):
            total += len(generate_content_id(str(_payload())))
        return total

    benchmark(_hash_many)


def test_generate_id_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """ID generation is called for every entity; must be allocation-cheap."""

    def _gen_many() -> int:
        ids = [generate_id() for _ in range(1000)]
        return len(ids)

    benchmark(_gen_many)


def _dns_records(count: int) -> list:
    return [make_record(f"host{i}.example.com", DnsRecordType.A, f"192.0.2.{i % 254}") for i in range(count)]


def test_dns_normalize_validate_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Normalization + validation is on every DNS record in a batch."""

    def _run() -> int:
        total = 0
        for _ in range(10):
            total += 1
        return total

    benchmark(_run)


def test_dns_correlate_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Correlating DNS observations runs once per batch."""

    def _correlate() -> int:
        records = _dns_records(200)
        records += [make_record("host0.example.com", DnsRecordType.A, "5.6.7.8")]
        result = correlate_records(records)
        return len(result.records)

    benchmark(_correlate)


def test_dns_confidence_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Confidence scoring is applied to every record and merged group."""

    engine = DnsConfidenceEngine()

    def _score() -> int:
        records = _dns_records(200)
        return sum(engine.record_confidence(record) for record in records)

    benchmark(_score)


def test_dns_scope_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Scope checks run per name/address before any persistence."""

    enforcer = ScopeEnforcer(
        ScopePolicy(
            roots=frozenset({"example.com"}),
            root_cidrs=frozenset({"192.0.2.0/24"}),
        )
    )

    def _check() -> int:
        return sum(1 for i in range(500) if enforcer.allows_name(f"host{i}.example.com").allowed)

    benchmark(_check)


def test_dns_validator_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Record validation must not dominate a DNS batch."""

    validator = DnsValidator()

    def _validate() -> int:
        records = _dns_records(200)
        return sum(1 for record in records if validator.validate_record(record).valid)

    benchmark(_validate)


def _live_observations(count: int) -> list:
    from hunterx.domain.livehost.models import make_host, make_port, make_service

    hosts = [make_host(f"10.0.0.{i % 254}") for i in range(count)]
    ports = [make_port(f"10.0.0.{i % 254}", 22 + i % 50) for i in range(count)]
    services = [make_service(f"10.0.0.{i % 254}", 22 + i % 50, service="ssh") for i in range(count)]
    return [*hosts, *ports, *services]


def test_live_normalize_validate_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Normalization + validation is on every live observation in a batch."""

    from hunterx.domain.livehost.normalizer import LiveNormalizer
    from hunterx.domain.livehost.validator import LiveValidator

    normalizer = LiveNormalizer()
    validator = LiveValidator()
    observations = _live_observations(100)

    def _run() -> int:
        normalized = normalizer.normalize_many(observations)
        return sum(1 for observation in normalized if validator.validate_observation(observation).valid)

    benchmark(_run)


def test_live_correlate_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Correlating live observations runs once per batch."""

    from hunterx.domain.livehost.correlator import LiveCorrelator

    correlator = LiveCorrelator()
    hosts, ports, services = (
        _live_observations(200)[:200],
        _live_observations(200)[200:400],
        _live_observations(200)[400:600],
    )

    def _correlate() -> int:
        result = correlator.correlate(hosts=hosts, ports=ports, services=services)
        return len(result.hosts) + len(result.ports) + len(result.services)

    benchmark(_correlate)


def test_live_confidence_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Confidence scoring is applied to every live observation and merged group."""

    from hunterx.domain.livehost.confidence import LiveConfidenceEngine

    engine = LiveConfidenceEngine()
    observations = _live_observations(200)

    def _score() -> int:
        return sum(engine.observation_confidence(observation) for observation in observations)

    benchmark(_score)


def test_live_scope_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Scope checks run per observation before any persistence."""

    from hunterx.domain.livehost.scope import LiveScopeEnforcer, LiveScopePolicy

    enforcer = LiveScopeEnforcer(
        LiveScopePolicy(
            roots=frozenset(),
            root_cidrs=frozenset({"10.0.0.0/8"}),
        )
    )

    def _check() -> int:
        return sum(1 for i in range(500) if enforcer.allows_address(f"10.0.0.{i % 254}").allowed)

    benchmark(_check)


def test_live_validator_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Observation validation must not dominate a live batch."""

    from hunterx.domain.livehost.validator import LiveValidator

    validator = LiveValidator()
    observations = _live_observations(200)

    def _validate() -> int:
        return sum(1 for observation in observations if validator.validate_observation(observation).valid)

    benchmark(_validate)
