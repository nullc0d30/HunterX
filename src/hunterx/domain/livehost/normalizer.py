# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery observation normalizer.

Turns raw observations from tool adapters into canonical records: canonical
(compressed) addresses, matching IP protocol versions, deduplicated method/
SAN/cipher/evidence sets, clamped latencies and confidences, and consistent
state/protocol/scheme spellings. Normalization is idempotent and pure — the
same raw input always yields the same normalized output and evidence (banners,
raw values) is never discarded.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from typing import TypeVar

from hunterx.domain.livehost.models import (
    HttpFinding,
    LiveBatch,
    LiveHost,
    PortFinding,
    PortState,
    ServiceFinding,
    TlsFinding,
    TransportProtocol,
    infer_ip_version,
)

_T = TypeVar("_T")


class LiveNormalizer:
    """Normalize raw live host & service observations into canonical records."""

    def normalize(self, observation: object) -> object:
        """Normalize a single observation by its runtime type."""
        if isinstance(observation, LiveHost):
            return self.normalize_host(observation)
        if isinstance(observation, PortFinding):
            return self.normalize_port(observation)
        if isinstance(observation, ServiceFinding):
            return self.normalize_service(observation)
        if isinstance(observation, TlsFinding):
            return self.normalize_tls(observation)
        if isinstance(observation, HttpFinding):
            return self.normalize_http(observation)
        return observation

    def normalize_many(self, observations: Iterable[object]) -> list[object]:
        """Normalize an iterable of observations, returning a list."""
        return [self.normalize(observation) for observation in observations]

    def normalize_host(self, host: LiveHost) -> LiveHost:
        """Return ``host`` with a canonical address/version and deduplicated methods."""
        return replace(
            host,
            ip_version=infer_ip_version(host.address),
            methods=_dedupe(host.methods),
            rtt_ms=_clamp_non_negative(host.rtt_ms),
            confidence=_clamp_confidence(host.confidence),
        )

    def normalize_port(self, port: PortFinding) -> PortFinding:
        """Return ``port`` with a canonical state and protocol."""
        return replace(
            port,
            state=_normalize_port_state(port.state),
            protocol=_normalize_protocol(port.protocol),
            confidence=_clamp_confidence(port.confidence),
        )

    def normalize_service(self, service: ServiceFinding) -> ServiceFinding:
        """Return ``service`` with collapsed whitespace and deduplicated evidence."""
        return replace(
            service,
            product=_collapse_ws(service.product),
            version=_collapse_ws(service.version),
            extrainfo=_collapse_ws(service.extrainfo),
            fingerprint_method=service.fingerprint_method.strip().lower(),
            evidence=_dedupe(service.evidence),
            confidence=_clamp_confidence(service.confidence),
        )

    def normalize_tls(self, tls: TlsFinding) -> TlsFinding:
        """Return ``tls`` with a canonical SHA-256 and deduplicated sets."""
        return replace(
            tls,
            sha256=tls.sha256.strip().lower(),
            san=_dedupe(tls.san),
            ciphers=_dedupe(tls.ciphers),
            confidence=_clamp_confidence(tls.confidence),
        )

    def normalize_http(self, http: HttpFinding) -> HttpFinding:
        """Return ``http`` with a canonical scheme and deduplicated tech hints."""
        return replace(
            http,
            scheme=http.scheme.strip().lower(),
            tech_hints=_dedupe(http.tech_hints),
            confidence=_clamp_confidence(http.confidence),
        )

    def normalize_batch(self, batch: LiveBatch) -> LiveBatch:
        """Normalize every observation carried by ``batch`` in place."""
        batch.hosts = [self.normalize_host(host) for host in batch.hosts]
        batch.ports = [self.normalize_port(port) for port in batch.ports]
        batch.services = [self.normalize_service(service) for service in batch.services]
        batch.tls = [self.normalize_tls(tls) for tls in batch.tls]
        batch.http = [self.normalize_http(http) for http in batch.http]
        return batch


def _dedupe(values: Iterable[_T]) -> tuple[_T, ...]:
    """Return ``values`` with duplicates removed, preserving first-seen order."""
    seen: set[str] = set()
    result: list[_T] = []
    for value in values:
        key = str(value).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(value)
    return tuple(result)


def _collapse_ws(value: str) -> str:
    """Collapse runs of whitespace in ``value`` (preserves inner spacing)."""
    return " ".join(str(value).split())


def _normalize_port_state(state: PortState) -> PortState:
    try:
        return PortState(str(state).lower())
    except ValueError:
        return PortState.UNKNOWN


def _normalize_protocol(protocol: TransportProtocol) -> TransportProtocol:
    try:
        return TransportProtocol(str(protocol).lower())
    except ValueError:
        return TransportProtocol.TCP


def _clamp_confidence(value: float) -> float:
    """Clamp a confidence score into ``[0, 1]``."""
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 1.0


def _clamp_non_negative(value: int) -> int:
    """Return ``value`` floored at zero (latency can never be negative)."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0
