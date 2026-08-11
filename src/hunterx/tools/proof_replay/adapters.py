# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Proof replay tool adapters.

Deterministic, in-process safe replay adapters used by the proof replay engine.
They only ever emit canonical observations derived from bounded inputs — they
never fetch, execute or modify anything outside the parameters they receive.
Every replay request has already passed the scope, safety and proof policy gates
of the proof service.

Replay is a proof demonstration, never a weaponization step: the adapter emits
an observation plus a deterministic replay verdict from the expected vs observed
behavior comparison, and never executes arbitrary payloads.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.vulnerability_proof.enums import ReplayResult, ReplayVerdict
from hunterx.domain.vulnerability_validation.enums import EvidenceComparison, EvidenceKind
from hunterx.domain.vulnerability_validation.evidence import compare_behavior
from hunterx.domain.vulnerability_validation.models import ValidationObservation
from hunterx.tools.safe_validation.base import ValidationToolAdapter, _observation

#: Canonical replay payload keys emitted by the adapter.
REPLAY_RESULT_KEY = "replay_result"
REPLAY_VERDICT_KEY = "replay_verdict"


class ProofReplayAdapter(ValidationToolAdapter):
    """Replay a proof and emit the deterministic replay verdict.

    The ``observations`` parameter carries a list of ``{"kind", "value",
    "confidence", "metadata"}`` entries that a caller (the proof service or a
    test harness) has already normalized. ``expected`` and ``observed`` drive
    the deterministic replay verdict.
    """

    descriptor = ToolDescriptor(
        name="proof-replay",
        version="1.0.0",
        description="Deterministic in-process safe proof replay probe.",
        entrypoint="hunterx.tools.proof_replay.adapters:ProofReplayAdapter",
        targets=("url", "host", "domain", "ip", "service"),
        capabilities=("safe-validation", "proof-replay"),
        parameters={
            "observations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "value": {"type": "string"},
                        "confidence": {"type": "number"},
                    },
                },
            },
            "expected": {"type": "string"},
            "observed": {"type": "string"},
            "target": {"type": "string"},
        },
        permissions=("none",),
    )

    def probe(
        self,
        context: ExecutionContext,
        *,
        target: str,
        parameters: dict[str, Any],
    ) -> list[ValidationObservation]:
        """Emit canonical observations and the replay verdict."""
        observations: list[ValidationObservation] = []
        for entry in parameters.get("observations") or ():
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if value is None:
                continue
            try:
                kind = EvidenceKind(str(entry.get("kind") or "external").lower())
            except ValueError:
                kind = EvidenceKind.EXTERNAL
            try:
                confidence = float(entry.get("confidence") or 1.0)
            except (TypeError, ValueError):
                confidence = 1.0
            observations.append(
                _observation(
                    kind,
                    str(value),
                    confidence=confidence,
                    source=context.tool_id,
                    metadata=dict(entry.get("metadata") or {}),
                )
            )
        expected = str(parameters.get("expected") or "")
        observed = str(parameters.get("observed") or "")
        result, verdict = _replay_verdict(expected, observed)
        metadata: dict[str, Any] = {
            "expected": expected,
            "observed": observed,
            REPLAY_RESULT_KEY: result.value,
            REPLAY_VERDICT_KEY: verdict.value,
            "target": target,
        }
        observations.append(
            _observation(
                EvidenceKind.BEHAVIORAL_DIFFERENTIAL,
                verdict.value,
                confidence=1.0 if verdict == ReplayVerdict.SUCCESS else 0.5,
                source=context.tool_id,
                metadata=metadata,
            )
        )
        return observations


def _replay_verdict(expected: str, observed: str) -> tuple[ReplayResult, ReplayVerdict]:
    """Compute the deterministic replay verdict from expected vs observed."""
    if not expected or not observed:
        return ReplayResult.INCONCLUSIVE, ReplayVerdict.INCONCLUSIVE
    comparison = compare_behavior(expected, observed)
    if comparison == EvidenceComparison.MATCH:
        return ReplayResult.SUCCESS, ReplayVerdict.SUCCESS
    if comparison == EvidenceComparison.MISMATCH:
        return ReplayResult.FAILED, ReplayVerdict.FAILED
    return ReplayResult.INCONCLUSIVE, ReplayVerdict.INCONCLUSIVE


def proof_replay_adapters() -> dict[str, ProofReplayAdapter]:
    """Return a fresh mapping of proof-replay tool id to adapter instance."""
    return {"proof-replay": ProofReplayAdapter()}


__all__ = [
    "REPLAY_RESULT_KEY",
    "REPLAY_VERDICT_KEY",
    "ProofReplayAdapter",
    "proof_replay_adapters",
]
