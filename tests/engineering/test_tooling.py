# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tool-invocation layer (eng.tooling)."""

from __future__ import annotations

import pathlib

from eng.tooling import ToolResult, ToolRunner


def test_tool_result_ok_and_combined() -> None:
    result = ToolResult(returncode=0, stdout="hi", stderr="err")
    assert result.ok is True
    assert result.combined == "hi\nerr"
    assert ToolResult(returncode=1).ok is False


def test_tool_runner_runs_real_command() -> None:
    runner = ToolRunner()
    result = runner.run(["python", "-c", "print('hello')"])
    assert result.ok
    assert "hello" in result.stdout
    assert result.executable == "python"


def test_tool_runner_returns_127_on_missing_executable() -> None:
    runner = ToolRunner()
    result = runner.run(["definitely-not-a-real-tool-xyz"])
    assert result.returncode == 127
    assert "not found" in result.stderr


def test_tool_runner_merges_env() -> None:
    runner = ToolRunner(env={"HX_TEST_VAR": "42"})
    result = runner.run(["python", "-c", "import os; print(os.environ['HX_TEST_VAR'])"])
    assert result.ok
    assert result.stdout.strip() == "42"


def test_tool_runner_timeout(tmp_path: pathlib.Path) -> None:
    runner = ToolRunner(timeout=1)
    result = runner.run(["python", "-c", "import time; time.sleep(5)"])
    assert result.returncode == 124


def test_available_detects_path() -> None:
    runner = ToolRunner()
    assert runner.available("python") is True
    assert runner.available("definitely-not-a-real-tool-xyz") is False
