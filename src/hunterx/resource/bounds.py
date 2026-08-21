# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — bounded in-memory state.

The durable system-of-record for a mission is the database (TIDB/SQLite): every
observation, hypothesis, decision, negative-evidence record and finding is
persisted as it is produced. The in-memory mission aggregate therefore only
needs to retain the working set the autonomous loop reasons over. To prevent
unbounded RAM growth while preserving important evidence, the in-memory lists
are bounded: settled/old entries beyond the configured cap are evicted from
memory only — the persisted copies remain the durable mission state.

Eviction never deletes evidence from the system of record and never drops
open work: open (unresolved) hypotheses, validated/verified findings and the
most recent observations are always retained.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from hunterx.resource.config import ResourceConfig


def _is_open_hypothesis(item: Any) -> bool:
    state = _value(item, "state")
    if isinstance(state, str) and state:
        return state in ("proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior")
    return False


def _is_important_finding(item: Any) -> bool:
    stage = str(_value(item, "stage") or "")
    return stage in ("verified", "proven", "report_ready", "supported")


def _value(item: Any, key: str) -> Any:
    if isinstance(item, dict):
        return item.get(key)
    return getattr(item, key, None)


def keep_recent(items: Iterable[Any], limit: int) -> list[Any]:
    """Return the most recent ``limit`` items of an ordered collection."""
    collected = list(items)
    if len(collected) <= limit:
        return collected
    return collected[-limit:]


def trim_observations(items: list[Any], limit: int) -> list[Any]:
    """Trim an append-only observation list to the most recent ``limit`` entries."""
    if len(items) <= limit:
        return items
    del items[: len(items) - limit]
    return items


def trim_decisions(items: list[Any], limit: int) -> list[Any]:
    """Trim an append-only decision list to the most recent ``limit`` entries."""
    if len(items) <= limit:
        return items
    del items[: len(items) - limit]
    return items


def trim_hypotheses(items: list[Any], limit: int) -> list[Any]:
    """Trim a hypothesis list, always keeping open hypotheses and important findings.

    Terminal hypotheses (refuted/disproved/rejected) beyond ``limit`` are
    dropped from memory first; if the list still exceeds ``limit`` the
    lowest-priority open hypotheses are dropped (bounded hypothesis storage).
    The persisted copies remain the durable mission state.
    """
    if len(items) <= limit:
        return items
    terminal = [item for item in items if not _is_open_hypothesis(item) and not _is_important_finding(item)]
    open_items = [item for item in items if _is_open_hypothesis(item) or _is_important_finding(item)]
    to_drop = len(items) - limit
    for item in terminal:
        if to_drop <= 0:
            break
        items.remove(item)
        to_drop -= 1
    if to_drop > 0 and open_items:
        # Preserve priority order: drop the lowest-priority open items first.
        def priority(item: Any) -> float:
            value = _value(item, "priority")
            try:
                return float(value) if value is not None else 0.5
            except (TypeError, ValueError):
                return 0.5

        for item in sorted(open_items, key=priority):
            if to_drop <= 0:
                break
            if item in items:
                items.remove(item)
            to_drop -= 1
    return items


def trim_generic(items: list[Any], limit: int) -> list[Any]:
    """Trim any append-only list to the most recent ``limit`` entries."""
    if len(items) <= limit:
        return items
    del items[: len(items) - limit]
    return items


def trim_mapping(mapping: dict[str, Any], limit: int) -> dict[str, Any]:
    """Trim an insertion-ordered mapping to the most recent ``limit`` keys."""
    if len(mapping) <= limit:
        return mapping
    overflow = len(mapping) - limit
    for key in list(mapping.keys())[:overflow]:
        mapping.pop(key, None)
    return mapping


def apply_mission_bounds(
    mission: Any,
    config: ResourceConfig,
) -> None:
    """Apply in-memory bounds to an orchestrated mission aggregate (in place).

    Only the in-memory working set is reduced; the TIDB persisted records are
    untouched. Safe to call after every persistence point.
    """
    if mission is None:
        return
    trim_observations(mission.observations, config.max_observations_in_memory)
    trim_hypotheses(mission.hypotheses, config.max_hypotheses_in_memory)
    trim_decisions(mission.decisions, config.max_decisions_in_memory)
    trim_generic(mission.trace, config.max_trace_in_memory)
    trim_generic(mission.negative_evidence, config.max_negative_evidence_in_memory)
    context = getattr(mission, "context", None)
    if context is not None:
        trim_generic(context.observations, config.max_observations_in_memory)
        trim_generic(context.decisions, config.max_decisions_in_memory)
        trim_generic(context.findings, config.max_evidence_in_memory)
        trim_generic(context.tool_executions, config.max_tool_executions_in_memory)
        trim_generic(context.attack_paths, config.max_attack_paths_in_memory)
        trim_generic(context.history, config.max_decisions_in_memory)
        trim_mapping(context.endpoints, config.max_evidence_in_memory)
        trim_mapping(context.parameters, config.max_evidence_in_memory)


__all__ = [
    "apply_mission_bounds",
    "keep_recent",
    "trim_decisions",
    "trim_generic",
    "trim_hypotheses",
    "trim_mapping",
    "trim_observations",
]
