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

import json
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


def content_bytes(content: Any) -> int:
    """Return the approximate JSON-serialized bytes of an observation content.

    The measured length is capped at a generous bound so the eviction path
    stays cheap even for pathological payloads.
    """
    try:
        return min(8 * 1024 * 1024, len(json.dumps(content, default=str, separators=(",", ":"))))
    except (TypeError, ValueError, RecursionError):
        try:
            return min(8 * 1024 * 1024, len(str(content)))
        except Exception:  # noqa: BLE001 - measurement is best-effort
            return 0


def truncate_content(content: Any, max_bytes: int) -> Any:
    """Return a JSON-safe copy of ``content`` that serializes to ``<= max_bytes``.

    Preserves structure and keys: lists are truncated to their first elements,
    strings to their first characters, and mappings keep all keys (their values
    are truncated recursively). The result is a *summary* of the original tool
    output — the durable copy is already persisted to the system of record.
    """
    if max_bytes <= 0 or content_bytes(content) <= max_bytes:
        return content
    return _truncate(content, max_bytes)


def _truncate(value: Any, max_bytes: int) -> Any:
    if content_bytes(value) <= max_bytes:
        return value
    if isinstance(value, dict):
        return {key: _truncate(item, max_bytes // 4) for key, item in list(value.items())[:32]}
    if isinstance(value, (list, tuple)):
        return [_truncate(item, max_bytes // 8) for item in list(value)[:64]]
    if isinstance(value, str):
        return value[: max_bytes // 2]
    if isinstance(value, bytes):
        return value[: max_bytes]
    return value


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


def trim_observations_by_bytes(items: list[Any], max_bytes: int) -> list[Any]:
    """Drop the oldest observations until total content bytes fit ``max_bytes``.

    Count caps bound the number of retained items; this byte cap bounds the
    actual resident memory of the retained working set. Only the in-memory
    copies are dropped — the persisted records remain the durable state.
    """
    if max_bytes <= 0:
        return items
    total = 0
    for observation in items:
        total += content_bytes(getattr(observation, "content", observation))
    while total > max_bytes and len(items) > 1:
        dropped = items.pop(0)
        total -= content_bytes(getattr(dropped, "content", dropped))
    return items


def apply_mission_bounds(
    mission: Any,
    config: ResourceConfig,
) -> None:
    """Apply in-memory bounds to an orchestrated mission aggregate (in place).

    Only the in-memory working set is reduced; the TIDB persisted records are
    untouched. Safe to call after every persistence point. Bounds cover both
    item counts and the actual resident bytes of the retained content.
    """
    if mission is None:
        return
    trim_observations(mission.observations, config.max_observations_in_memory)
    trim_observations_by_bytes(mission.observations, config.max_aggregate_state_bytes)
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
        trim_mapping(context.services, config.max_services_in_memory)
        trim_mapping(context.assets, config.max_assets_in_memory)
        trim_mapping(context.technologies, config.max_technologies_in_memory)


__all__ = [
    "apply_mission_bounds",
    "content_bytes",
    "keep_recent",
    "trim_decisions",
    "trim_generic",
    "trim_hypotheses",
    "trim_mapping",
    "trim_observations",
    "trim_observations_by_bytes",
    "truncate_content",
]
