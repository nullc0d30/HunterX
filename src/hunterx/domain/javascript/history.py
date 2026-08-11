# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Historical comparison for JavaScript intelligence.

Compares a previous JavaScript state (an earlier correlated run for the same
target) with the current correlated run and produces :class:`JSChange` records
for added, removed and changed subjects. The comparison is keyed on canonical
finding keys so reordering or cosmetic differences never produce noise.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from hunterx.domain.javascript.models import JSChange
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class JSHistorySnapshot:
    """An immutable snapshot of the JavaScript state of a target.

    Attributes:
        target_key: canonical owning host key.
        subjects: mapping ``artifact_type -> canonical key -> value``.
        recorded_at: UTC ISO snapshot timestamp.

    """

    target_key: str
    subjects: dict[str, dict[str, str]]
    recorded_at: str = ""

    @classmethod
    def from_batch(cls, batch: object, *, target_key: str = "") -> JSHistorySnapshot:
        """Build a snapshot from a correlated batch-like object.

        ``batch`` may be a :class:`JavaScriptBatch` or any object exposing the
        correlated list attributes (``endpoints``, ``routes``, ...).
        """
        target = target_key or getattr(getattr(batch, "target", None), "value", "")
        subjects: dict[str, dict[str, str]] = {}
        for artifact_type, values in _iter_artifacts(batch):
            subjects[artifact_type] = {
                value.key(): str(value.to_dict())
                for value in values
                if hasattr(value, "key") and hasattr(value, "to_dict")
            }
        return cls(
            target_key=target,
            subjects=subjects,
            recorded_at=utcnow_iso(),
        )


class JSHistory:
    """Diff two snapshots and emit :class:`JSChange` records."""

    def compare(
        self,
        previous: JSHistorySnapshot,
        current: JSHistorySnapshot,
        *,
        source: str = "javascript",
    ) -> list[JSChange]:
        """Return the changes between ``previous`` and ``current``."""
        changes: list[JSChange] = []
        now = utcnow_iso()

        artifact_types = set(previous.subjects) | set(current.subjects)
        for artifact_type in sorted(artifact_types):
            before = previous.subjects.get(artifact_type, {})
            after = current.subjects.get(artifact_type, {})
            for key in sorted(set(before) | set(after)):
                if key not in before:
                    changes.append(
                        JSChange(
                            artifact_type=artifact_type,
                            subject=key,
                            change_type="added",
                            previous="",
                            current=after[key],
                            detected_at=now,
                            source=source,
                        )
                    )
                elif key not in after:
                    changes.append(
                        JSChange(
                            artifact_type=artifact_type,
                            subject=key,
                            change_type="removed",
                            previous=before[key],
                            current="",
                            detected_at=now,
                            source=source,
                        )
                    )
                elif before[key] != after[key]:
                    changes.append(
                        JSChange(
                            artifact_type=artifact_type,
                            subject=key,
                            change_type="changed",
                            previous=before[key],
                            current=after[key],
                            detected_at=now,
                            source=source,
                        )
                    )
        return changes


def _iter_artifacts(batch: object) -> Iterable[tuple[str, Iterable[object]]]:
    """Yield ``(artifact_type, values)`` pairs from a batch-like object."""
    kinds = (
        "endpoints",
        "routes",
        "auth",
        "domains",
        "services",
        "storage",
        "secrets",
        "technology",
        "dependencies",
        "configuration",
        "workers",
        "wasm",
        "security",
        "dynamic_imports",
    )
    for kind in kinds:
        values = getattr(batch, kind, None) or ()
        yield kind, values
