# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the Autonomous Mission Orchestration CLI.

Builds the full platform and drives the ``hunterx mission ...`` command group:
create/start/status/pause/resume/cancel/finalize plus timeline/decisions/
hypotheses/findings/attack-paths/coverage/tools views.
"""

from __future__ import annotations

import json

import pytest

from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.platform import build_platform


@pytest.fixture()
def app() -> CliApplication:
    cli = CliApplication()
    register_default_commands(cli, build_platform())
    return cli


class TestMissionCLI:
    def _run(self, app: CliApplication, capsys: pytest.CaptureFixture[str], *argv: str) -> dict[str, object]:
        assert app.run(list(argv)) == 0
        return json.loads(capsys.readouterr().out)

    def test_create_and_status(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        created = self._run(app, capsys, "mission", "create", "full_security_assessment", "https://example.com")
        assert created.get("mission_id")
        mission_id = created["mission_id"]
        status = self._run(app, capsys, "mission", "status", str(mission_id))
        assert status["mission_id"] == mission_id
        assert status["current_phase"] == "target_modeling"

    def test_start_timeline_tools(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        mission_id = self._run(app, capsys, "mission", "create", "bug_bounty_hunt", "https://example.com")["mission_id"]
        self._run(app, capsys, "mission", "start", str(mission_id))
        timeline = self._run(app, capsys, "mission", "timeline", str(mission_id))
        assert isinstance(timeline, list)
        assert self._run(app, capsys, "mission", "tools", str(mission_id)) == []

    def test_coverage_and_hypotheses(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        mission_id = self._run(app, capsys, "mission", "create", "api_assessment", "https://example.com")["mission_id"]
        self._run(app, capsys, "mission", "start", str(mission_id))
        coverage = self._run(app, capsys, "mission", "coverage", str(mission_id))
        assert "coverage_ratio" in coverage
        hypotheses = self._run(app, capsys, "mission", "hypotheses", str(mission_id))
        assert hypotheses == []

    def test_finalize(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        mission_id = self._run(app, capsys, "mission", "create", "full_security_assessment", "https://example.com")["mission_id"]
        finalized = self._run(app, capsys, "mission", "finalize", str(mission_id))
        assert finalized.get("outcome") is not None

    def test_attack_paths_and_decisions(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        mission_id = self._run(app, capsys, "mission", "create", "pentest", "https://example.com")["mission_id"]
        assert self._run(app, capsys, "mission", "attack-paths", str(mission_id)) == []
        assert self._run(app, capsys, "mission", "decisions", str(mission_id)) == []
        assert self._run(app, capsys, "mission", "findings", str(mission_id)) == []
