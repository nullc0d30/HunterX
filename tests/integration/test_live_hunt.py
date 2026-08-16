# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the live ``hunterx hunt`` CLI experience.

Verifies that ``hunt`` keeps the established stdout JSON contract while
rendering real lifecycle events on stderr and recording run artifacts, and
that ``--json`` (machine mode) keeps stdout pure JSON and stderr quiet while
artifacts are still recorded.
"""

from __future__ import annotations

import json

from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.platform import build_platform
from tests.framework.fakes import FakeExecutionEngine
from tests.integration.test_mission_execution_lifecycle import _FAKE_OUTPUTS, _PassingReadiness

_TARGET = "https://juice-shop.herokuapp.com"


def _live_platform():
    platform = build_platform()
    platform.mission_execution_service._engine = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))  # noqa: SLF001
    platform.mission_execution_service._readiness = _PassingReadiness()  # noqa: SLF001
    return platform


def _app(platform) -> CliApplication:  # noqa: ANN001
    app = CliApplication()
    register_default_commands(app, platform)
    return app


def _read_jsonl(path) -> list[dict]:  # noqa: ANN001
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


class TestLiveHuntCLI:
    def test_live_hunt_renders_progress_on_stderr_and_json_on_stdout(self, capsys, tmp_path) -> None:  # noqa: ANN001, ANN003
        app = _app(_live_platform())

        assert app.run(["hunt", "full_security_assessment", _TARGET, "--output", str(tmp_path)]) == 0
        captured = capsys.readouterr()
        overview = json.loads(captured.out)

        # stdout stays the established pure-JSON contract.
        assert overview["mission_id"]
        assert overview["counts"]["tool_executions"] > 0
        assert overview["planning_state"] == "completed"
        # human progress lives on stderr only.
        assert "[HUNT]" in captured.err
        assert ">> run" in captured.err
        # artifacts are recorded and referenced.
        events = _read_jsonl(tmp_path / "events.jsonl")
        event_types = {event["event_type"] for event in events}
        assert "mission.tool.started" in event_types
        assert "mission.phase.started" in event_types
        assert "coverage.updated" in event_types
        results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
        assert results["status"] == "completed"
        assert results["event_count"] == len(events)
        assert (tmp_path / "report.txt").read_text(encoding="utf-8")
        assert overview["artifacts"]["events"].endswith("events.jsonl")

    def test_json_mode_keeps_stdout_pure_and_stderr_quiet(self, capsys, tmp_path) -> None:  # noqa: ANN001, ANN003
        app = _app(_live_platform())

        assert app.run(["hunt", "--json", "full_security_assessment", _TARGET, "--output", str(tmp_path)]) == 0
        captured = capsys.readouterr()
        overview = json.loads(captured.out)

        assert overview["counts"]["tool_executions"] > 0
        assert "[HUNT]" not in captured.err
        assert ">> run" not in captured.err
        # artifacts are still recorded in machine mode.
        events = _read_jsonl(tmp_path / "events.jsonl")
        assert any(event["event_type"] == "mission.tool.started" for event in events)
        results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
        assert results["status"] == "completed"
        assert (tmp_path / "report.txt").exists()
