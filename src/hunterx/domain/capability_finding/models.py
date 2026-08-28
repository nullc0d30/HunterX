# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Models for the universal capability-finding lifecycle.

A :class:`CapabilityCandidate` is the lossless hand-off between the
capability-execution engine (Phase 5) and the validated-finding lifecycle
(Phase 6): it retains the capability, surface, request/response evidence,
baseline/differential facts, auth context, strategy and confidence so the
candidate never needs to be re-discovered to be promoted, replayed or
reported.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.capability_finding.enums import ReproductionVerdict
from hunterx.shared.ids import generate_id


@dataclass(frozen=True, slots=True)
class RequestReconstruction:
    """Deterministic, redacted reconstruction of the finding request.

    Headers are intentionally excluded — they may carry session cookies and
    must never leak into replay records or PoC artifacts. Cookies are
    referenced as a presence flag only.
    """

    method: str = "GET"
    url: str = ""
    parameter: str = ""
    baseline_payload: str = ""
    payloads: tuple[str, ...] = ()
    mutations: tuple[str, ...] = ()
    body: str = ""
    cookie_present: bool = False
    session_state: str = "anonymous"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the reconstruction (payloads are the proof vectors)."""
        return {
            "method": self.method,
            "url": self.url,
            "parameter": self.parameter,
            "baseline_payload": self.baseline_payload,
            "payloads": list(self.payloads),
            "mutations": list(self.mutations),
            "body": self.body[:400],
            "cookie_present": self.cookie_present,
            "session_state": self.session_state,
            "redacted": "headers omitted; cookies referenced as presence only",
        }


@dataclass(frozen=True, slots=True)
class ReplayAttempt:
    """One isolated replay of the candidate probe."""

    index: int = 0
    confirmed: bool = False
    signal: str = "none"
    baseline_status: int | None = None
    attack_status: int | None = None
    duration_ms: int = 0
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the replay attempt."""
        return {
            "index": self.index,
            "confirmed": self.confirmed,
            "signal": self.signal,
            "baseline_status": self.baseline_status,
            "attack_status": self.attack_status,
            "duration_ms": self.duration_ms,
            "recorded_at": self.recorded_at,
        }


@dataclass(frozen=True, slots=True)
class CapabilityCandidate:
    """Lossless hand-off record from capability execution to the lifecycle."""

    candidate_id: str
    finding_class: str
    capability_id: str
    mission_id: str
    surface_key: str
    endpoint: str
    vector: str
    session_state: str
    strategies: tuple[str, ...]
    tools: tuple[str, ...]
    evidence: dict[str, Any]
    confidence: float | None
    request_summaries: tuple[dict[str, Any], ...]
    response_summaries: tuple[dict[str, Any], ...]
    recorded_at: str
    chain: tuple[str, ...] = ()
    replay_attempts: tuple[ReplayAttempt, ...] = ()
    reproduction: ReproductionVerdict | None = None
    remediation: dict[str, Any] = field(default_factory=dict)
    severity: str = "low"
    severity_reasons: tuple[str, ...] = ()

    @classmethod
    def from_capability_record(cls, record: Any) -> CapabilityCandidate:
        """Build the candidate from a capability-execution record (lossless)."""
        return cls(
            candidate_id=generate_id(),
            finding_class=str(record.capability_id).replace("-", "_"),
            capability_id=record.capability_id,
            mission_id=record.mission_id,
            surface_key=record.surface_key,
            endpoint=record.endpoint,
            vector=record.vector,
            session_state=record.session_state,
            strategies=tuple(record.strategies or ()),
            tools=tuple(tool.tool_id for tool in (record.tools or ())),
            evidence=dict(record.evidence or {}),
            confidence=record.confidence,
            request_summaries=tuple(record.request_summaries or ()),
            response_summaries=tuple(record.response_summaries or ()),
            recorded_at=record.recorded_at,
            chain=tuple(record.chain or ()),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the candidate (JSON-safe)."""
        return {
            "candidate_id": self.candidate_id,
            "finding_class": self.finding_class,
            "capability_id": self.capability_id,
            "mission_id": self.mission_id,
            "surface_key": self.surface_key,
            "endpoint": self.endpoint,
            "vector": self.vector,
            "session_state": self.session_state,
            "strategies": list(self.strategies),
            "tools": list(self.tools),
            "evidence": dict(self.evidence),
            "confidence": self.confidence,
            "request_summaries": [dict(item) for item in self.request_summaries],
            "response_summaries": [dict(item) for item in self.response_summaries],
            "recorded_at": self.recorded_at,
            "chain": list(self.chain),
            "replay_attempts": [attempt.to_dict() for attempt in self.replay_attempts],
            "reproduction": self.reproduction.value if self.reproduction else None,
            "remediation": dict(self.remediation),
            "severity": self.severity,
            "severity_reasons": list(self.severity_reasons),
        }


@dataclass(frozen=True, slots=True)
class Remediation:
    """Class-specific remediation guidance for a finding."""

    vulnerability_class: str
    title: str
    steps: tuple[str, ...]
    references: tuple[str, ...]
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the remediation guide."""
        return {
            "vulnerability_class": self.vulnerability_class,
            "title": self.title,
            "steps": list(self.steps),
            "references": list(self.references),
            "rationale": self.rationale,
        }


__all__ = [
    "CapabilityCandidate",
    "ReplayAttempt",
    "RequestReconstruction",
    "Remediation",
    "ReproductionVerdict",
]
