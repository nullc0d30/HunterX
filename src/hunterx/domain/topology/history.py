# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology temporal history.

Compares the previous persisted topology with the newly correlated one and
produces temporal changes (new/removed/changed). History merging preserves the
earliest ``first_seen`` while advancing ``last_seen`` so the temporal model is
append-only and explainable.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from hunterx.domain.topology.enums import ChangeType
from hunterx.domain.topology.models import GraphRelationship, TopologyChange


class TopologyHistory:
    """Diff two generations of a topology graph."""

    def diff(
        self,
        previous: Mapping[str, GraphRelationship],
        current: Mapping[str, GraphRelationship],
        *,
        mission_id: str = "",
        correlation_id: str = "",
    ) -> tuple[list[GraphRelationship], list[TopologyChange]]:
        """Return ``(merged_edges, changes)`` comparing current against previous."""
        merged: list[GraphRelationship] = []
        changes: list[TopologyChange] = []

        for key in sorted(current):
            edge = current[key]
            prior = previous.get(key)
            if prior is None:
                changes.append(
                    self._change(key, ChangeType.NEW, "", edge.as_dict(), mission_id, correlation_id)
                )
                merged.append(edge)
            else:
                merged_edge = self._advance(prior, edge)
                merged.append(merged_edge)
                if self._changed(prior, edge):
                    changes.append(
                        self._change(
                            key, ChangeType.CHANGED, prior.as_dict(), edge.as_dict(), mission_id, correlation_id
                        )
                    )

        for key in sorted(previous):
            if key not in current:
                changes.append(
                    self._change(key, ChangeType.REMOVED, previous[key].as_dict(), "", mission_id, correlation_id)
                )

        return merged, changes

    @staticmethod
    def _advance(prior: GraphRelationship, current: GraphRelationship) -> GraphRelationship:
        """Merge a prior edge with its current form, preserving temporal state."""
        sources = list(prior.sources)
        for source in current.sources:
            if source not in sources:
                sources.append(source)
        evidence: dict[str, Any] = dict(prior.evidence)
        for source, entries in current.evidence.items():
            evidence.setdefault(source, []).extend(entries if isinstance(entries, list) else [entries])
        current.sources = sources
        current.evidence = evidence
        if current.first_seen and prior.first_seen:
            current.first_seen = min(current.first_seen, prior.first_seen)
        else:
            current.first_seen = current.first_seen or prior.first_seen
        current.last_seen = current.last_seen or prior.last_seen
        if prior.in_scope and current.in_scope:
            current.in_scope = True
        current.attributes.setdefault("history", {"revisions": prior.attributes.get("history", {}).get("revisions", 0) + 1})
        return current

    @staticmethod
    def _changed(prior: GraphRelationship, current: GraphRelationship) -> bool:
        if set(prior.sources) != set(current.sources):
            return True
        if abs(prior.confidence - current.confidence) > 0.05:
            return True
        if (prior.source_id or None) != (current.source_id or None):
            return True
        if (prior.target_id or None) != (current.target_id or None):
            return True
        return bool(current.attributes.get("shared_delta"))

    @staticmethod
    def _change(
        key: str,
        change_type: str,
        old_value: Any,
        new_value: Any,
        mission_id: str,
        correlation_id: str,
    ) -> TopologyChange:
        return TopologyChange(
            kind="relationship",
            key=key,
            change_type=change_type.value if isinstance(change_type, ChangeType) else str(change_type),
            old_value=_json(old_value),
            new_value=_json(new_value),
            tool_id="",
            confidence=1.0,
            mission_id=mission_id,
            correlation_id=correlation_id,
        )


def _json(value: Any) -> str:
    import json

    if value == "":
        return ""
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
