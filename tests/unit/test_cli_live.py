# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the live mission console and artifact recording.

Covers the command redaction guarantees (secrets must never reach the bus or
the artifacts), the renderer's mapping of real lifecycle events to stderr
lines, the recorder's ``events.jsonl``/``results.json``/``report.txt``
artifacts, and the real ``BinaryRunner`` command-observer seam publishing
redacted commands.
"""

from __future__ import annotations

import io
import json
import sys

from hunterx.cli.live import LiveMissionRenderer, MissionRunRecorder, redact_command
from hunterx.domain.events import DomainEvent
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.tools.recon.runner import (
    BinaryRunner,
    bind_active_execution,
    clear_active_execution,
)

_MISSION_ID = "mission-test-1"


class TestRedactCommand:
    def test_masks_secret_option_values(self) -> None:
        assert redact_command(["nuclei", "--token", "abc123"]) == "nuclei --token a****3"
        assert redact_command(["curl", "--api-key=xyz"]) == "curl --api-key=x*z"
        assert redact_command(["hx", "-o", "report", "--password", "hunter2", "target"]) == (
            "hx -o report --password h*****2 target"
        )

    def test_masks_header_style_values(self) -> None:
        assert redact_command(["curl", "-H", "Authorization: Bearer abcdef"]) == (
            "curl -H Authorization: B***********f"
        )

    def test_masks_url_credentials(self) -> None:
        masked = redact_command(["curl", "https://user:pass@example.com/path"])
        assert "user:pass@" not in masked
        assert "***" in masked
        assert "example.com" in masked

    def test_masks_jwt_shaped_tokens(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        masked = redact_command(["probe", jwt])
        assert jwt not in masked
        assert "***" in masked

    def test_keeps_harmless_commands_intact(self) -> None:
        assert redact_command(["nmap", "-sV", "-p", "80,443", "example.com"]) == (
            "nmap -sV -p 80,443 example.com"
        )


class TestLiveMissionRenderer:
    def _renderer(self, stream: io.StringIO) -> tuple[InMemoryEventBus, LiveMissionRenderer]:
        bus = InMemoryEventBus()
        renderer = LiveMissionRenderer(bus, mission_id=_MISSION_ID, stream=stream)
        return bus, renderer

    def test_renders_lifecycle_events_as_progress_lines(self) -> None:
        stream = io.StringIO()
        bus, renderer = self._renderer(stream)

        bus.publish(
            DomainEvent(
                event_type="mission.started",
                payload={
                    "mission_id": _MISSION_ID,
                    "objective": "full_security_assessment",
                    "target": "https://example.com",
                    "strategy": "adaptive",
                },
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="mission.phase.started",
                payload={"mission_id": _MISSION_ID, "phase": "reconnaissance"},
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="mission.tool.started",
                payload={
                    "mission_id": _MISSION_ID,
                    "tool_id": "nuclei",
                    "capability": "vulnerability_scanning",
                    "target": "https://example.com",
                },
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="tool.command",
                payload={"mission_id": _MISSION_ID, "command": "nuclei --token ****** -u https://example.com"},
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="mission.tool.completed",
                payload={
                    "mission_id": _MISSION_ID,
                    "tool_id": "nuclei",
                    "outcome": "evidence",
                    "duration_ms": 120,
                },
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="mission.tool.failed",
                payload={"mission_id": _MISSION_ID, "tool_id": "nmap", "error": "boom"},
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="coverage.updated",
                payload={
                    "mission_id": _MISSION_ID,
                    "asset_key": "example.com",
                    "capability": "vulnerability_scanning",
                    "state": "tested",
                    "tool_id": "nuclei",
                },
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(event_type="mission.completed", payload={"mission_id": _MISSION_ID}, mission_id=_MISSION_ID)
        )
        # Events of other missions are never rendered.
        bus.publish(
            DomainEvent(
                event_type="mission.tool.started",
                payload={"mission_id": "other", "tool_id": "nmap"},
                mission_id="other",
            )
        )

        text = stream.getvalue()
        assert "[HUNT]" in text
        assert "RECONNAISSANCE" in text
        assert ">> run nuclei" in text
        assert "$ nuclei --token ******" in text
        assert "ok nuclei" in text
        assert "FAIL nmap" in text
        assert "coverage: vulnerability_scanning = tested" in text
        assert "[DONE]" in text
        assert ">> run nmap" not in text
        renderer.close()

    def test_renderer_ignores_events_after_close(self) -> None:
        stream = io.StringIO()
        bus, renderer = self._renderer(stream)
        renderer.close()
        bus.publish(
            DomainEvent(
                event_type="mission.tool.started",
                payload={"mission_id": _MISSION_ID, "tool_id": "nuclei"},
                mission_id=_MISSION_ID,
            )
        )
        assert ">> run" not in stream.getvalue()

    def test_summary_renders_counts_and_artifacts(self) -> None:
        stream = io.StringIO()
        bus, renderer = self._renderer(stream)
        renderer.summary(
            {
                "status": "executed",
                "mission_id": _MISSION_ID,
                "target_id": "https://example.com",
                "planning_state": "completed",
                "current_phase": "reporting",
                "coverage_ratio": 0.5,
                "counts": {"assets": 3, "findings": 1},
                "artifacts": {"report": "/tmp/report.txt"},
            }
        )
        text = stream.getvalue()
        assert "EXECUTED" in text
        assert "https://example.com" in text
        assert "/tmp/report.txt" in text
        renderer.close()


class TestMissionRunRecorder:
    def test_records_events_and_writes_artifacts(self, tmp_path) -> None:  # noqa: ANN001
        bus = InMemoryEventBus()
        recorder = MissionRunRecorder(bus, mission_id=_MISSION_ID, output_dir=tmp_path)
        bus.publish(
            DomainEvent(
                event_type="mission.started",
                payload={"mission_id": _MISSION_ID},
                mission_id=_MISSION_ID,
            )
        )
        bus.publish(
            DomainEvent(
                event_type="mission.tool.started",
                payload={"mission_id": _MISSION_ID, "tool_id": "nuclei"},
                mission_id=_MISSION_ID,
            )
        )
        # Events of other missions are never recorded.
        bus.publish(
            DomainEvent(
                event_type="mission.tool.started",
                payload={"mission_id": "other", "tool_id": "nmap"},
                mission_id="other",
            )
        )

        paths = recorder.finish(
            {"mission_id": _MISSION_ID, "status": "executed", "counts": {"assets": 1}},
            status="executed",
        )
        # finish() is idempotent.
        assert recorder.finish({}, status="again") == paths

        events = [
            json.loads(line) for line in (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        assert [event["event_type"] for event in events] == ["mission.started", "mission.tool.started"]

        results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
        assert results["status"] == "executed"
        assert results["event_count"] == 2
        assert results["artifact_paths"]["events"].endswith("events.jsonl")

        report = (tmp_path / "report.txt").read_text(encoding="utf-8")
        assert "HUNTERX MISSION REPORT" in report
        assert "EXECUTIVE SUMMARY" in report
        recorder.close()

    def test_runner_observer_publishes_redacted_commands(self, tmp_path) -> None:  # noqa: ANN001
        bus = InMemoryEventBus()
        recorder = MissionRunRecorder(bus, mission_id=_MISSION_ID, output_dir=tmp_path)
        try:
            bind_active_execution(
                mission_id=_MISSION_ID,
                tool_id="nuclei",
                execution_id="exec-1",
                capability="vulnerability_scanning",
                action_id="act-1",
                target="https://example.com",
            )
            runner = BinaryRunner()
            result = runner.run(
                [sys.executable, "-c", "print('hi')", "--token", "supersecret"],
                tool_id="nuclei",
            )
            assert result.returncode == 0
        finally:
            clear_active_execution()
            recorder.close()

        command_events = [event for event in recorder.events() if event["event_type"] == "tool.command"]
        assert command_events, "a command event must be recorded"
        payload = command_events[-1]["payload"]
        assert payload["mission_id"] == _MISSION_ID
        assert payload["tool_id"] == "nuclei"
        assert payload["execution_id"] == "exec-1"
        assert "supersecret" not in payload["command"]
        assert "***" in payload["command"]

    def test_unobserved_executions_publish_nothing(self, tmp_path) -> None:  # noqa: ANN001
        bus = InMemoryEventBus()
        recorder = MissionRunRecorder(bus, mission_id=_MISSION_ID, output_dir=tmp_path)
        try:
            runner = BinaryRunner()
            result = runner.run([sys.executable, "-c", "print('hi')"], tool_id="nuclei")
            assert result.returncode == 0
        finally:
            recorder.close()
        assert not [event for event in recorder.events() if event["event_type"] == "tool.command"]
