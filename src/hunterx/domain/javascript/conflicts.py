# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Conflict handling for JavaScript intelligence.

When two tools or two assets disagree about the same artifact (for example two
endpoints with the same key but different confidence, or a technology with two
claimed versions), the resolver preserves the disagreement as a
:class:`JSAnalysisConflict` and selects a canonical value by confidence and
evidence strength. Nothing is silently dropped — contradictions become first
class records.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.javascript.models import JSAnalysisConflict
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ConflictResolution:
    """The result of resolving one conflict.

    Attributes:
        subject: the affected artifact identifier.
        artifact_type: the artifact class.
        selected: the canonical value selected.
        reason: why it was selected.
        confidence: confidence in the selection in ``[0, 1]``.
        conflict: the preserved :class:`JSAnalysisConflict`.

    """

    subject: str
    artifact_type: str
    selected: str
    reason: str
    confidence: float
    conflict: JSAnalysisConflict


class JSConflictResolver:
    """Resolve disagreements between observations of the same artifact."""

    def resolve(
        self,
        subject: str,
        artifact_type: str,
        observations: list[dict[str, object]],
        *,
        mission_id: str = "",
        correlation_id: str = "",
    ) -> ConflictResolution | None:
        """Resolve the disagreement among ``observations``.

        ``observations`` are dicts with at least ``value`` and ``confidence``
        keys. When all observations agree on the value, no conflict is
        recorded and ``None`` is returned.
        """
        if not observations:
            return None
        if all(
            str(item.get("value")) == str(observations[0].get("value"))
            for item in observations[1:]
        ):
            return None

        selected = max(
            observations,
            key=lambda item: (float(item.get("confidence") or 0.0), _evidence_count(item)),
        )
        selected_value = str(selected.get("value"))
        reason = _reason_for(selected_value, observations)
        confidence = float(selected.get("confidence") or 0.0)
        conflict = JSAnalysisConflict(
            subject=subject,
            artifact_type=artifact_type,
            observations=tuple(dict(item) for item in observations),
            selected=selected_value,
            reason=reason,
            confidence=confidence,
            detected_at=utcnow_iso(),
        )
        return ConflictResolution(
            subject=subject,
            artifact_type=artifact_type,
            selected=selected_value,
            reason=reason,
            confidence=confidence,
            conflict=conflict,
        )


def _reason_for(selected_value: str, observations: list[dict[str, object]]) -> str:
    """Build a human-readable selection reason."""
    agreement = len(
        {
            str(item.get("value"))
            for item in observations
            if str(item.get("value")) == selected_value
        }
    )
    total = len(observations)
    return f"selected value '{selected_value}' by highest confidence/evidence (agreed by {agreement}/{total} observations)"


def _evidence_count(item: dict[str, object]) -> int:
    evidence = item.get("evidence")
    if isinstance(evidence, (list, tuple)):
        return len(evidence)
    return 0
