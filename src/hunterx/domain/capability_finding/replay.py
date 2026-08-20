# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deterministic replay for validated-finding reproduction.

Replay re-executes the candidate probe against the same loopback target using
the differential transport (:class:`ProbeExecutor`) — a dedicated raw-HTTP
path that shares no state with the discovery services, so replay traffic is
isolated from ordinary discovery traffic. Replay is deterministic: the probe
is rebuilt from the candidate's retained evidence (same method, endpoint,
parameter and payloads) and re-analyzed with the capability engine.

Secrets are handled safely: cookies are injected but never recorded (only
``cookie_present`` is kept), and headers never enter replay records.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from hunterx.domain.capability_finding.models import CapabilityCandidate, ReplayAttempt
from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor, is_loopback_target


class ReplayEngine:
    """Replay a candidate's probe in isolation and classify reproduction."""

    def __init__(
        self,
        *,
        attempts: int = 3,
        executor: ProbeExecutor | None = None,
        capability_engine: VulnerabilityCapabilityEngine | None = None,
        cookie: str = "",
    ) -> None:
        self._attempts = max(1, attempts)
        self._executor = executor or ProbeExecutor()
        self._capability_engine = capability_engine or VulnerabilityCapabilityEngine()
        self._cookie = cookie

    @property
    def cookie(self) -> str:
        """The session cookie used for authenticated replay (never recorded)."""
        return self._cookie

    def _probe_for(self, candidate: CapabilityCandidate) -> Any:
        """Rebuild the candidate's probe deterministically from its evidence."""
        evidence = {
            "endpoint": candidate.endpoint,
            "parameter": candidate.vector,
            "method": "GET",
            "content_type": "",
            "fetch_hint": False,
            "object_hint": False,
            "observed_status": "",
            "confidence": candidate.confidence,
        }
        probe = self._capability_engine.build_probe(candidate.capability_id, evidence)
        if probe is None:
            raise ValueError(f"no probe constructible for {candidate.capability_id} on {candidate.endpoint}")
        if self._cookie:
            probe = replace(probe, headers=tuple((*probe.headers, ("Cookie", self._cookie))))
        return probe

    def replay(self, candidate: CapabilityCandidate) -> tuple[ReplayAttempt, ...]:
        """Replay the probe ``attempts`` times; return the attempt series.

        Every attempt is a fresh isolated execution; the recorded series is
        the evidence for :class:`ReproductionClassifier`.
        """
        from hunterx.shared.time import utcnow_iso

        if not is_loopback_target(candidate.endpoint):
            raise PermissionError(f"replay refused: '{candidate.endpoint}' is not a loopback target")
        probe = self._probe_for(candidate)
        attempts: list[ReplayAttempt] = []
        for index in range(self._attempts):
            responses = self._executor.execute(probe, target=candidate.endpoint)
            verdict = self._capability_engine.analyze_probe(candidate.capability_id, probe, responses)
            baseline = responses[0] if responses else {}
            attacks = responses[1:] if responses else []
            attempts.append(
                ReplayAttempt(
                    index=index,
                    confirmed=bool(verdict.supported),
                    signal=verdict.signal.value,
                    baseline_status=baseline.get("status"),
                    attack_status=next((r.get("status") for r in attacks if r.get("status")), baseline.get("status")),
                    duration_ms=sum(int(r.get("elapsed_ms") or 0) for r in responses),
                    recorded_at=utcnow_iso(),
                )
            )
        return tuple(attempts)


__all__ = ["ReplayEngine", "is_loopback_target"]
