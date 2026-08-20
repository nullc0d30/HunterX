# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability execution — records, tool orchestration, coverage persistence.

The machine-readable coverage model every capability produces:

    capability -> {status, applicable surfaces, context, tasks generated /
    executed / failed / blocked, verification attempts, result, reason,
    strategies, tools}

Persisted with the mission as ``capability_coverage.json``. Every field is
derived from what actually executed — never from the catalog alone.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.capability_execution.enums import STATUS_PRECEDENCE, CapabilityExecutionStatus
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ToolExecutionRecord:
    """One tool execution: what ran, what it returned, what it parsed.

    ``exit_code`` is ``None`` when the tool was never invoked (honest
    ``unavailable``), ``0`` on success, non-zero on failure. ``parsed_result``
    is the structured conclusion (verdict signal or finding count).
    """

    tool_id: str
    surface: str = ""
    command: str = ""
    exit_code: int | None = None
    stdout_status: str = ""      # "ok" / "unavailable" / "failed" / "no-output"
    parsed_result: Any = None
    duration_ms: int = 0
    strategy: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize a tool-execution record to a JSON-safe mapping."""
        return {
            "tool": self.tool_id,
            "surface": self.surface,
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout_status": self.stdout_status,
            "parsed_result": self.parsed_result,
            "duration_ms": self.duration_ms,
            "strategy": self.strategy,
            "error": self.error,
        }


@dataclass(frozen=True, slots=True)
class CapabilityExecutionRecord:
    """Per-(capability x surface x context) execution outcome."""

    mission_id: str
    capability_id: str
    surface_key: str
    endpoint: str = ""
    vector: str = ""              # parameter / path / method / header ...
    session_state: str = "anonymous"
    outcome: CapabilityExecutionStatus = CapabilityExecutionStatus.NOT_APPLICABLE
    reason: str = ""
    strategies: tuple[str, ...] = ()
    requests: int = 0
    verification_attempts: int = 0
    findings: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None
    request_summaries: tuple[dict[str, Any], ...] = ()
    response_summaries: tuple[dict[str, Any], ...] = ()
    tools: tuple[ToolExecutionRecord, ...] = ()
    chain: tuple[str, ...] = ()   # discovery -> signal -> surface -> capability
    recorded_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize a capability-execution record to a JSON-safe mapping."""
        return {
            "capability": self.capability_id,
            "surface": self.surface_key,
            "endpoint": self.endpoint,
            "vector": self.vector,
            "session_state": self.session_state,
            "outcome": self.outcome.value,
            "reason": self.reason,
            "strategies": list(self.strategies),
            "requests": self.requests,
            "verification_attempts": self.verification_attempts,
            "findings": self.findings,
            "evidence": dict(self.evidence),
            "confidence": self.confidence,
            "request_summaries": [dict(item) for item in self.request_summaries],
            "response_summaries": [dict(item) for item in self.response_summaries],
            "tools": [tool.to_dict() for tool in self.tools],
            "chain": list(self.chain),
            "recorded_at": self.recorded_at,
        }


def aggregate_status(records: list[CapabilityExecutionRecord]) -> CapabilityExecutionStatus:
    """Return the exactly-one authoritative status for a capability.

    Precedence: FINDING > BLOCKED > FAILED > VERIFIED > NO_FINDING >
    NOT_APPLICABLE. Without records the caller decides from mapping state
    (never from assumption).
    """
    if not records:
        return CapabilityExecutionStatus.NOT_APPLICABLE
    outcomes = {record.outcome for record in records}
    for status in STATUS_PRECEDENCE:
        if status in outcomes:
            return status
    return CapabilityExecutionStatus.NO_FINDING


@dataclass(frozen=True, slots=True)
class CapabilityCoverage:
    """One capability's authoritative coverage summary."""

    capability_id: str
    status: CapabilityExecutionStatus
    applicable_surfaces: int = 0
    surfaces: tuple[str, ...] = ()
    tasks_generated: int = 0
    tasks_executed: int = 0
    tasks_failed: int = 0
    tasks_blocked: int = 0
    verification_attempts: int = 0
    result: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    strategies: tuple[str, ...] = ()
    auth_contexts: tuple[str, ...] = ()
    tools: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize a coverage entry to a JSON-safe mapping."""
        return {
            "status": self.status.value,
            "applicable_surfaces": self.applicable_surfaces,
            "surfaces": list(self.surfaces),
            "tasks_generated": self.tasks_generated,
            "tasks_executed": self.tasks_executed,
            "tasks_failed": self.tasks_failed,
            "tasks_blocked": self.tasks_blocked,
            "verification_attempts": self.verification_attempts,
            "result": dict(self.result),
            "reason": self.reason,
            "strategies": list(self.strategies),
            "auth_contexts": list(self.auth_contexts),
            "tools": [dict(tool) for tool in self.tools],
        }


def build_capability_coverage(
    records: list[CapabilityExecutionRecord],
    catalog: list[str],
    *,
    mapped_capabilities: set[str] | None = None,
    queued_capabilities: set[str] | None = None,
    mission_id: str = "",
    target: str = "",
) -> dict[str, Any]:
    """Build the full ``capability_coverage`` document.

    Every capability in the live catalog receives exactly one authoritative
    status:

        * with execution records: aggregated by :func:`aggregate_status`;
        * mapped but never executed (a queue task existed): BLOCKED — a mapped
          capability that did not run is blocked, never complete;
        * never mapped to any discovered surface characteristic:
          NOT_APPLICABLE — concluded from target evidence, never assumption.

    Args:
        records: execution records for this mission.
        catalog: capability ids from the live catalog.
        mapped_capabilities: capability ids that were mapped to a surface
            (an assignment existed).
        queued_capabilities: capability ids with at least one queued task.
        mission_id: owning mission id.
        target: authorized target key.

    """
    mapped = mapped_capabilities or set()
    queued = queued_capabilities or set()
    by_capability: dict[str, list[CapabilityExecutionRecord]] = {}
    for record in records:
        by_capability.setdefault(record.capability_id, []).append(record)

    capabilities: dict[str, Any] = {}
    for capability_id in sorted(catalog):
        capability_records = by_capability.get(capability_id, [])
        surfaces = sorted({record.surface_key for record in capability_records})
        if capability_records:
            status = aggregate_status(capability_records)
            reason = _aggregate_reason(capability_records, status)
            findings = sum(record.findings for record in capability_records)
            result = {"findings": findings, "supported_verdicts": findings}
        elif capability_id in mapped or capability_id in queued:
            status = CapabilityExecutionStatus.BLOCKED
            reason = "mapped to a discovered surface but its task never executed"
            findings = 0
            result = {"findings": 0}
        else:
            status = CapabilityExecutionStatus.NOT_APPLICABLE
            reason = "not mapped to any discovered surface characteristic"
            findings = 0
            result = {"findings": 0}

        strategies = tuple(sorted({s for record in capability_records for s in record.strategies}))
        auth_contexts = tuple(sorted({record.session_state for record in capability_records}))
        tools = tuple(
            tool.to_dict() for record in capability_records for tool in record.tools
        )
        capabilities[capability_id] = CapabilityCoverage(
            capability_id=capability_id,
            status=status,
            applicable_surfaces=len(surfaces),
            surfaces=tuple(surfaces),
            tasks_generated=len(capability_records),
            tasks_executed=sum(1 for r in capability_records if r.outcome in (CapabilityExecutionStatus.FINDING, CapabilityExecutionStatus.VERIFIED, CapabilityExecutionStatus.NO_FINDING)),
            tasks_failed=sum(1 for r in capability_records if r.outcome is CapabilityExecutionStatus.FAILED),
            tasks_blocked=sum(1 for r in capability_records if r.outcome is CapabilityExecutionStatus.BLOCKED),
            verification_attempts=sum(record.verification_attempts for record in capability_records),
            result=result,
            reason=reason,
            strategies=strategies,
            auth_contexts=auth_contexts,
            tools=tools,
        ).to_dict()

    summary = {status.value: 0 for status in CapabilityExecutionStatus}
    for entry in capabilities.values():
        summary[entry["status"]] += 1
    return {
        "mission_id": mission_id,
        "target": target,
        "generated_at": utcnow_iso(),
        "catalog_size": len(catalog),
        "statuses": summary,
        "capabilities": capabilities,
    }


def _aggregate_reason(
    records: list[CapabilityExecutionRecord],
    status: CapabilityExecutionStatus,
) -> str:
    """Pick the most informative reason for the aggregated status."""
    for record in records:
        if record.outcome is status and record.reason:
            return record.reason
    return f"aggregated from {len(records)} execution record(s)"


__all__ = [
    "CapabilityCoverage",
    "CapabilityExecutionRecord",
    "ToolExecutionRecord",
    "aggregate_status",
    "build_capability_coverage",
]
