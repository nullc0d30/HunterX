# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence conflict resolution.

When multiple observations disagree about one cloud subject, the conflict
resolver picks a deterministic winner (highest confidence, ties broken by
source priority then lexicographic value) and records the disagreement. It is
pure and never validates or contacts anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.cloud.models import CloudConflict


@dataclass(frozen=True, slots=True)
class CloudConflictResult:
    """The outcome of resolving a group of disagreeing observations.

    Attributes:
        selected: the winning observation.
        conflict: the recorded disagreement (``None`` when unanimous).
        source_order: source priority used for deterministic tie-breaking.

    """

    selected: Any
    conflict: CloudConflict | None
    source_order: tuple[str, ...] = field(
        default=("dns", "http", "web", "technology", "javascript", "documentation", "tidb", "cloud", "tool")
    )


class CloudConflictResolver:
    """Resolve disagreements between observations deterministically."""

    def resolve(
        self,
        observations: list[Any],
        *,
        subject: str,
        subject_type: str,
        conflict_type: str = "identity",
        source_order: tuple[str, ...] | None = None,
    ) -> CloudConflictResult:
        """Return the deterministic winner and any recorded conflict."""
        if not observations:
            raise ValueError("cannot resolve an empty observation group")
        order = tuple(source_order) if source_order is not None else _DEFAULT_SOURCE_ORDER
        winner = max(
            observations,
            key=lambda obs: (
                float(getattr(obs, "confidence", 0.0) or 0.0),
                _source_priority(str(getattr(obs, "source", "") or ""), order),
                _value_of(obs),
            ),
        )
        values = {_value_of(obs) for obs in observations}
        if len(values) <= 1:
            return CloudConflictResult(selected=winner, conflict=None, source_order=order)
        conflict = CloudConflict(
            subject=subject,
            subject_type=subject_type,
            conflict_type=conflict_type,
            observations=tuple(_payload(obs) for obs in observations),
            selected=_value_of(winner),
            selected_source=str(getattr(winner, "source", "") or ""),
            reason=f"conflicting {subject_type} cloud intelligence across sources",
            confidence=float(getattr(winner, "confidence", 0.0) or 0.0),
        )
        return CloudConflictResult(selected=winner, conflict=conflict, source_order=order)


_DEFAULT_SOURCE_ORDER: tuple[str, ...] = (
    "dns",
    "http",
    "web",
    "api",
    "technology",
    "javascript",
    "documentation",
    "tidb",
    "cloud",
    "tool",
)


def _source_priority(source: str, order: tuple[str, ...]) -> int:
    """Return the priority index of ``source`` (lower wins; unknown sources last)."""
    try:
        return order.index(source.lower())
    except ValueError:
        return len(order)


def _value_of(observation: Any) -> str:
    """Return the deterministic comparison value of an observation."""
    if hasattr(observation, "name"):
        return str(getattr(observation, "name", "") or "")
    if hasattr(observation, "value"):
        return str(getattr(observation, "value", "") or "")
    return str(observation)


def _payload(observation: Any) -> dict[str, Any]:
    """Serialize an observation for conflict provenance."""
    if hasattr(observation, "to_dict"):
        serialized = observation.to_dict()
        if isinstance(serialized, dict):
            return serialized
    return {
        "type": type(observation).__name__,
        "source": str(getattr(observation, "source", "") or ""),
        "value": _value_of(observation),
    }
