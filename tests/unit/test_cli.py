# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI framework."""

from __future__ import annotations

import pytest

from hunterx.cli.app import CliApplication, main
from hunterx.cli.render import OutputRenderer


class TestCliApplication:
    def test_registered_command_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        app = CliApplication()
        app.registry.register("hello", lambda argv: (print("hi") or 0), help_text="Say hi")
        assert app.run(["hello"]) == 0
        assert capsys.readouterr().out.strip() == "hi"

    def test_nested_command_resolution(self, capsys: pytest.CaptureFixture[str]) -> None:
        app = CliApplication()

        def handler(argv: list[str]) -> int:
            print("mission", " ".join(argv))
            return 0

        app.registry.register("mission start", handler, help_text="Start a mission")
        assert app.run(["mission", "start", "abc"]) == 0
        assert capsys.readouterr().out.strip() == "mission abc"

    def test_unknown_command_returns_two(self, capsys: pytest.CaptureFixture[str]) -> None:
        app = CliApplication()
        assert app.run(["bogus"]) == 2
        assert "Usage:" in capsys.readouterr().err

    def test_main_returns_zero(self) -> None:
        assert main(["version"]) == 0

    def test_main_config(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["config"]) == 0
        out = capsys.readouterr().out
        assert "app_name" in out


class TestOutputRenderer:
    def test_json(self) -> None:
        assert '"a"' in OutputRenderer().render({"a": 1}, fmt="json")

    def test_yaml(self) -> None:
        assert "a: 1" in OutputRenderer().render({"a": 1}, fmt="yaml")

    def test_csv(self) -> None:
        out = OutputRenderer().render([{"a": 1, "b": 2}], fmt="csv")
        assert out.splitlines()[0] == "a,b"

    def test_text_dict(self) -> None:
        assert "a: 1" in OutputRenderer().render({"a": 1}, fmt="text")

    def test_unsupported_format(self) -> None:
        with pytest.raises(ValueError):
            OutputRenderer().render({}, fmt="xml")
