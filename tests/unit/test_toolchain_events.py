# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Sprint 031 typed tool events and catalog entries."""

from __future__ import annotations

from hunterx.domain.events.catalog import build_registry
from hunterx.domain.events.types import (
    ToolEvidenceExtractedEvent,
    ToolExecutionCompletedEvent,
    ToolExecutionFailedEvent,
    ToolExecutionStartedEvent,
    ToolHealthFailedEvent,
    ToolObservationCreatedEvent,
    ToolOutputNormalizedEvent,
    ToolOutputParsedEvent,
    ToolOutputReceivedEvent,
    ToolRecommendationCreatedEvent,
    ToolResultContradictionEvent,
    ToolVersionDetectedEvent,
)

_REQUIRED_EVENT_TYPES = {
    "tool.execution.started",
    "tool.execution.completed",
    "tool.execution.failed",
    "tool.output.received",
    "tool.output.parsed",
    "tool.output.normalized",
    "tool.evidence.extracted",
    "tool.observation.created",
    "tool.result.contradiction",
    "tool.health.failed",
    "tool.version.detected",
    "tool.recommendation.created",
}


def test_all_toolchain_events_are_catalogued() -> None:
    registry = build_registry()
    registered = {spec.event_type for spec in registry.specs() if spec.event_type.startswith("tool.")}
    assert _REQUIRED_EVENT_TYPES.issubset(registered)


def test_execution_events_carry_execution_metadata() -> None:
    started = ToolExecutionStartedEvent("exec-1", "nmap", mission_id="m1", target_id="t1", scope_id="s1")
    assert started.event_type == "tool.execution.started"
    assert started.payload["tool_id"] == "nmap"

    completed = ToolExecutionCompletedEvent("exec-1", "nmap", exit_code=0, semantics="found", duration_ms=10)
    assert completed.event_type == "tool.execution.completed"
    assert completed.payload["semantics"] == "found"

    failed = ToolExecutionFailedEvent("exec-2", "dnsx", failure_kind="timeout", message="deadline")
    assert failed.event_type == "tool.execution.failed"
    assert failed.payload["failure_kind"] == "timeout"


def test_output_events_carry_parser_normalizer_ids() -> None:
    received = ToolOutputReceivedEvent("e", "ffuf", formats=["json"], size_bytes=42)
    assert received.event_type == "tool.output.received"
    assert received.payload["formats"] == ["json"]

    parsed = ToolOutputParsedEvent("e", "ffuf", parser_id="ffuf-json", records=3)
    assert parsed.event_type == "tool.output.parsed"
    assert parsed.payload["records"] == 3

    normalized = ToolOutputNormalizedEvent("e", "ffuf", normalizer_id="content-normalizer", observations=2)
    assert normalized.event_type == "tool.output.normalized"
    assert normalized.payload["observations"] == 2


def test_evidence_observation_contradiction_events() -> None:
    evidence = ToolEvidenceExtractedEvent("e", "nuclei", "ev-1", evidence_class="candidate", evidence_type="sqli-candidate")
    assert evidence.event_type == "tool.evidence.extracted"
    assert evidence.payload["evidence_class"] == "candidate"

    observation = ToolObservationCreatedEvent("e", "nmap", "obs-1", observation_kind="port")
    assert observation.event_type == "tool.observation.created"
    assert observation.payload["observation_kind"] == "port"

    contradiction = ToolResultContradictionEvent("port.443", "10.0.0.1", tools=["nmap", "naabu"], vulnerability_class="service")
    assert contradiction.event_type == "tool.result.contradiction"
    assert contradiction.payload["tools"] == ["nmap", "naabu"]


def test_health_version_recommendation_events() -> None:
    health = ToolHealthFailedEvent("sqlmap", status="unavailable", reason="missing binary")
    assert health.event_type == "tool.health.failed"
    assert health.payload["reason"] == "missing binary"

    version = ToolVersionDetectedEvent("nuclei", "3.3.0", compatible=True)
    assert version.event_type == "tool.version.detected"
    assert version.payload["compatible"] is True

    recommendation = ToolRecommendationCreatedEvent("sqli-detection", "sqlmap", kind="best", score=0.9, reason="best fit")
    assert recommendation.event_type == "tool.recommendation.created"
    assert recommendation.payload["score"] == 0.9
