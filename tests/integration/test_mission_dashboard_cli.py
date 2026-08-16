# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the Sprint 033 ``hunterx hunt`` CLI command group.

Builds the full platform and drives the ``hunt`` command family: ``hunt``
(create+start), ``hunt status``, ``hunt surface``, ``hunt coverage``,
``hunt findings``, ``hunt evidence``, ``hunt proofs``, ``hunt paths`` and
``hunt timeline``.
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


class TestHuntCLI:
    def _run(self, app: CliApplication, capsys: pytest.CaptureFixture[str], *argv: str) -> dict[str, object] | list[object]:
        assert app.run(list(argv)) == 0
        return json.loads(capsys.readouterr().out)

    def test_hunt_creates_and_starts_mission(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        created = self._run(app, capsys, "hunt", "bug_bounty_hunt", "https://example.com")
        assert isinstance(created, dict)
        assert created.get("mission_id")
        assert created["objective"] == "bug_bounty_hunt"
        # ``hunt`` runs the mission to completion, so the final phase reflects
        # the finished workflow (REPORTING) — never a stuck target_modeling.
        assert created["current_phase"] == "reporting"

    def test_hunt_status_surface(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        mission_id = str(self._run(app, capsys, "hunt", "api_assessment", "https://api.example.com")["mission_id"])
        status = self._run(app, capsys, "hunt", "status", mission_id)
        assert isinstance(status, dict) and status["mission_id"] == mission_id
        surface = self._run(app, capsys, "hunt", "surface", mission_id)
        assert isinstance(surface, dict) and surface["mission_id"] == mission_id

    def test_hunt_evidence_proofs_paths_timeline(self, app: CliApplication, capsys: pytest.CaptureFixture[str]) -> None:
        mission_id = str(self._run(app, capsys, "hunt", "full_security_assessment", "https://example.com")["mission_id"])
        for sub in ("coverage", "findings", "evidence", "proofs", "paths", "timeline"):
            payload = self._run(app, capsys, "hunt", sub, mission_id)
            assert payload is not None, sub

    def test_hunt_commands_registered(self, app: CliApplication) -> None:
        names = app.registry.names()
        for expected in ("hunt", "hunt status", "hunt surface", "hunt coverage", "hunt findings", "hunt evidence", "hunt proofs", "hunt paths", "hunt timeline"):
            assert expected in names, expected
