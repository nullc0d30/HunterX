# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence conflict resolution.

Detects and resolves disagreements between sources over the same API subject:
version differences, identity disagreements, documentation/source conflicts and
method mismatches. Resolution is deterministic — documented spec evidence beats
inferred hints, stronger evidence beats weaker, and the rationale is preserved
as a :class:`ApiConflict` record.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.api.models import ApiConflict, ApiOperationObservation


class ApiConflictResolver:
    """Detect and resolve API intelligence conflicts deterministically.

    Usage::

        resolver = ApiConflictResolver()
        conflict = resolver.detect_operation_conflict(truth, candidates)
        resolved = resolver.resolve_operation(truth, candidates)
    """

    def detect_operation_conflict(
        self,
        truth: ApiOperationObservation,
        candidates: Sequence[ApiOperationObservation],
    ) -> ApiConflict | None:
        """Return a conflict when candidates disagree with the truth record."""
        disagreements: list[dict[str, Any]] = []
        for item in candidates:
            if item is truth:
                continue
            issues: list[str] = []
            if item.auth_required != truth.auth_required:
                issues.append("auth_required")
            if item.surface_form != truth.surface_form:
                issues.append("surface_form")
            if item.api_kind != truth.api_kind:
                issues.append("api_kind")
            if item.operation_id and truth.operation_id and item.operation_id != truth.operation_id:
                issues.append("operation_id")
            if issues:
                disagreements.append(
                    {
                        "source": item.source,
                        "tool_id": item.tool_id,
                        "issues": issues,
                        "api_kind": item.api_kind.value,
                        "surface_form": item.surface_form.value,
                        "auth_required": item.auth_required,
                    }
                )
        if not disagreements:
            return None
        return ApiConflict(
            subject=truth.key(),
            subject_type="operation",
            observations=tuple(disagreements),
            conflict_type="identity",
            selected=truth.path,
            selected_source=truth.source,
            reason="duplicate observations disagreed on operation attributes; documented spec evidence selected",
            confidence=truth.confidence,
        )

    def resolve_operation(
        self,
        truth: ApiOperationObservation,
        candidates: Sequence[ApiOperationObservation],
    ) -> ApiOperationObservation:
        """Resolve disagreements by selecting the documented truth record."""
        return truth

    def detect_version_conflict(
        self,
        subject: str,
        versions: Sequence[tuple[str, str, float]],
    ) -> ApiConflict | None:
        """Detect a version disagreement for ``subject``.

        ``versions`` is a sequence of ``(value, source, confidence)`` tuples.
        """
        distinct = {value for value, _, _ in versions if value}
        if len(distinct) <= 1:
            return None
        best = max(versions, key=lambda pair: (pair[2], 1 if pair[1] else 0))
        observations = tuple(
            {"value": value, "source": source, "confidence": confidence} for value, source, confidence in versions
        )
        return ApiConflict(
            subject=subject,
            subject_type="version",
            observations=observations,
            conflict_type="version",
            selected=best[0],
            selected_source=best[1],
            reason="sources disagreed on API version; highest-confidence source selected",
            confidence=best[2],
        )
