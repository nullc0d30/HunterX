# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 7 — real Arjun invocation against a local vulnerable fixture.

Proves the fixed adapter end-to-end: a valid command is built, Arjun runs
against the local fixture, its JSON report is read back and converted into the
existing parameter observation contract, and readiness reports the fixed
invocation as healthy (not broken).

Requires the real ``arjun`` binary on PATH (skipped otherwise).
"""

from __future__ import annotations

import shutil

import pytest

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.parameter.adapters import ArjunAdapter
from hunterx.tools.readiness.models import ToolReadinessStatus
from tests.framework.vulnerable_app import VulnerableApp

pytestmark = pytest.mark.skipif(
    shutil.which("arjun") is None,
    reason="arjun is not installed on this environment",
)

_WORDLIST = ["q", "id", "search", "page", "limit", "filter", "name", "sort"]


@pytest.fixture
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


def _wordlist(tmp_path) -> str:  # noqa: ANN001
    path = tmp_path / "arjun-params.txt"
    path.write_text("\n".join(_WORDLIST), encoding="utf-8")
    return str(path)


def test_arjun_invocation_succeeds_and_produces_parameter_observation(app: VulnerableApp, tmp_path) -> None:  # noqa: ANN001, ANN003
    # The reflection endpoint varies its body with benign parameter values, so
    # arjun reliably detects the parameter without requiring an error payload.
    target = app.base_url + "/vuln/echo"
    context = ExecutionContext(
        tool_id="arjun",
        target=target,
        correlation_id="phase7",
        timeout_seconds=120,
        parameters={"wordlist": _wordlist(tmp_path)},
    )
    adapter = ArjunAdapter()
    argv = adapter.build_argv(context)
    assert "-oJ" in argv and not argv[argv.index("-oJ") + 1].startswith("-")

    result = adapter.runner.run(argv, timeout_s=120, tool_id="arjun")

    assert result.returncode == 0, result.stderr
    records = adapter.parse_output(context, result)
    adapter.cleanup(context)

    names = {record.get("name") for record in records}
    assert "q" in names, names
    assert records, "arjun must convert its report into parameter observations"
    record = next(r for r in records if r.get("name") == "q")
    assert record.get("endpoint") == target
    assert record.get("method") == "GET"
    assert record.get("tool_id") == "arjun"
    assert record.get("correlation_id") == "phase7"


def test_readiness_reports_fixed_arjun_as_available(app: VulnerableApp) -> None:
    # The real health check (binary exists + adapter invocation accepted)
    # must NOT mark the fixed arjun invocation as broken.
    from hunterx.platform import build_platform

    platform = build_platform()
    verdict = platform.tool_readiness_service.check(tool_ids=["arjun"]).tools[0]
    assert verdict.status is ToolReadinessStatus.AVAILABLE, verdict.error
