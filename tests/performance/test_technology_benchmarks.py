# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for technology fingerprinting.

Benchmarks are executed by the performance quality gate with pytest-benchmark.
They cover the hot paths of the capability: signature detection, name
normalization/resolution, version extraction, confidence scoring, correlation
and validation throughput for large observation sets.
"""

from __future__ import annotations

from hunterx.domain.technology.confidence import TechnologyConfidenceEngine
from hunterx.domain.technology.correlator import TechnologyCorrelator
from hunterx.domain.technology.detector import HttpEvidence, SignatureDetector
from hunterx.domain.technology.models import (
    EvidenceStrength,
    EvidenceType,
    TechnologyEvidence,
    make_observation,
)
from hunterx.domain.technology.normalizer import TechnologyNormalizer
from hunterx.domain.technology.resolver import TechnologyResolver
from hunterx.domain.technology.validator import TechnologyValidator
from hunterx.domain.technology.version import VersionResolver


def test_normalize_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Name normalization runs for every raw detection."""

    normalizer = TechnologyNormalizer()

    def _run() -> int:
        total = 0
        for _ in range(500):
            total += len(normalizer.normalize_name("nginx/1.24.0").normalized)
        return total

    benchmark(_run)


def test_resolve_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Resolution maps every raw name onto the canonical taxonomy."""

    resolver = TechnologyResolver()

    def _run() -> int:
        total = 0
        for i in range(500):
            name = "nginx/1.24.0" if i % 2 else "Apache httpd"
            total += len(resolver.resolve(name).canonical_name)
        return total

    benchmark(_run)


def test_version_extract_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Version extraction is applied to every version-bearing observation."""

    resolver = VersionResolver()

    def _run() -> int:
        total = 0
        for _ in range(500):
            total += len(resolver.extract("nginx/1.24.0").version)
        return total

    benchmark(_run)


def test_detector_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Signature detection runs once per fetched evidence bundle."""

    detector = SignatureDetector()
    evidence = HttpEvidence(
        url="https://shop.example.com",
        status_code=200,
        headers={"Server": "nginx/1.24.0", "cf-ray": "abc123", "X-Powered-By": "PHP/8.1.2"},
        html="<html><body>wp-content bootstrap react</body></html>",
        meta={"generator": "WordPress 6.4.3"},
    )

    def _run() -> int:
        return len(detector.detect(evidence, asset="shop.example.com"))

    benchmark(_run)


def test_confidence_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Confidence scoring is applied to every observation."""

    engine = TechnologyConfidenceEngine()
    observation = make_observation(
        "example.com",
        "nginx",
        canonical_name="Nginx",
        tool_id="httpx",
        evidence=(
            TechnologyEvidence(
                evidence_type=EvidenceType.RESPONSE_HEADER,
                value="server: nginx",
                strength=EvidenceStrength.STRONG,
            ),
        ),
    )

    def _run() -> int:
        total = 0.0
        for _ in range(200):
            total += engine.observation_confidence(observation)
        return int(total)

    benchmark(_run)


def test_correlate_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Correlation merges observations across tools once per batch."""

    correlator = TechnologyCorrelator()
    tools = ("httpx", "whatweb", "signature", "nmap")

    def _build(count: int) -> list:
        observations = []
        for i in range(count):
            tool = tools[i % len(tools)]
            observations.append(
                make_observation(
                    f"host{i % 50}.example.com",
                    "Nginx" if i % 3 else "PHP",
                    canonical_name="Nginx" if i % 3 else "PHP",
                    version=f"1.{i % 10}.0",
                    tool_id=tool,
                    source=tool,
                )
            )
        return observations

    def _run() -> int:
        result = correlator.correlate(_build(300))
        return len(result.technologies)

    benchmark(_run)


def test_validate_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Validation runs for every observation before persistence."""

    validator = TechnologyValidator()
    observations = [make_observation(f"host{i}.example.com", "Nginx", canonical_name="Nginx") for i in range(200)]

    def _run() -> int:
        return len(validator.filter_valid(observations))

    benchmark(_run)


def test_correlate_1k_observations(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Large observation sets must correlate in bounded time."""

    correlator = TechnologyCorrelator()
    tools = ("httpx", "whatweb", "signature")

    def _build(count: int) -> list:
        return [
            make_observation(
                f"host{i % 200}.example.com",
                "Nginx" if i % 4 else "WordPress",
                canonical_name="Nginx" if i % 4 else "WordPress",
                version=f"{i % 9}.{i % 5}.0",
                tool_id=tools[i % len(tools)],
                source=tools[i % len(tools)],
            )
            for i in range(count)
        ]

    def _run() -> int:
        return len(correlator.correlate(_build(1000)).technologies)

    benchmark(_run)
