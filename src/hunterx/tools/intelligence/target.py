# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target intelligence (Sprint 023).

Records what HunterX has already done to a target and answers "what do we
already know?" and "what should we NOT repeat?". Every execution writes a
:class:`ToolExecutionRecord`; the store composes these into a
:class:`TargetIntelligenceSnapshot` the planner and executor consult.
"""

from __future__ import annotations

from datetime import UTC, datetime
from threading import RLock

from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    TargetIntelligenceSnapshot,
    ToolExecutionRecord,
)


class TargetIntelligenceStore:
    """Thread-safe per-target execution history and snapshot builder.

    Usage::

        store = TargetIntelligenceStore()
        store.record(execution_record, observations)
        snapshot = store.snapshot("example.com")
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._history: dict[str, list[ToolExecutionRecord]] = {}
        self._observations: dict[str, list[CanonicalObservation]] = {}
        self._exclusions: dict[str, list[str]] = {}

    def record(
        self,
        record: ToolExecutionRecord,
        observations: list[CanonicalObservation] | None = None,
    ) -> None:
        """Persist an execution record (and optional observations) for its target."""
        with self._lock:
            self._history.setdefault(record.target, []).append(record)
            if observations:
                self._observations.setdefault(record.target, []).extend(observations)

    def exclude(self, target: str, reason: str) -> None:
        """Mark a target or check as excluded (never re-run)."""
        with self._lock:
            self._exclusions.setdefault(target, [])
            if reason not in self._exclusions[target]:
                self._exclusions[target].append(reason)

    def history(self, target: str) -> tuple[ToolExecutionRecord, ...]:
        """Return execution records for ``target``, newest first."""
        with self._lock:
            records = self._history.get(target, [])
            return tuple(reversed(records))

    def has_executed(self, target: str, tool_id: str) -> bool:
        """Return ``True`` when ``tool_id`` already ran against ``target``."""
        with self._lock:
            return any(r.tool_id == tool_id for r in self._history.get(target, ()))

    def snapshot(self, target: str) -> TargetIntelligenceSnapshot:
        """Build the current intelligence snapshot for ``target``."""
        with self._lock:
            records = tuple(reversed(self._history.get(target, ())))
            observations = self._observations.get(target, [])

            assets = _dedup(o.value for o in observations if o.observation_kind == "asset")
            services = _dedup(o.value for o in observations if o.observation_kind == "service")
            technologies = _dedup(
                o.value for o in observations if o.observation_kind == "technology"
            )
            endpoints = _dedup(o.value for o in observations if o.observation_kind == "url")
            parameters = _dedup(
                o.value for o in observations if o.observation_kind == "parameter"
            )
            vulnerabilities = _dedup(
                o.value for o in observations if o.observation_kind == "vulnerability"
            )
            evidence = _dedup(o.observation_id for o in observations)

            tool_coverage: dict[str, tuple[str, ...]] = {}
            for observation in observations:
                tool_coverage.setdefault(observation.tool_id, [])
                if observation.observation_id not in tool_coverage[observation.tool_id]:
                    tool_coverage[observation.tool_id].append(observation.observation_id)
            tool_coverage = {k: tuple(v) for k, v in tool_coverage.items()}

            confidence_state: dict[str, float] = {}
            for category, values in (
                ("assets", assets),
                ("services", services),
                ("technologies", technologies),
                ("endpoints", endpoints),
                ("vulnerabilities", vulnerabilities),
            ):
                if values:
                    confidence_state[category] = min(1.0, len(values) / 5.0 + 0.2)

            return TargetIntelligenceSnapshot(
                target=target,
                known_assets=assets,
                known_services=services,
                known_technologies=technologies,
                known_endpoints=endpoints,
                known_parameters=parameters,
                known_vulnerabilities=vulnerabilities,
                known_evidence=evidence,
                known_exclusions=tuple(self._exclusions.get(target, ())),
                first_seen=_first_seen(records),
                last_seen=_last_seen(records),
                tool_coverage=tool_coverage,
                confidence_state=confidence_state,
                execution_history=records,
            )


def _dedup(values) -> tuple[str, ...]:
    seen: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
    return tuple(seen)


def _first_seen(records: tuple[ToolExecutionRecord, ...]) -> str:
    return records[0].started_at if records else ""


def _last_seen(records: tuple[ToolExecutionRecord, ...]) -> str:
    return records[0].completed_at if records else ""


def utc_now() -> str:
    """Return a UTC ISO-8601 timestamp."""
    return datetime.now(UTC).isoformat()


__all__ = ["TargetIntelligenceStore", "utc_now"]
