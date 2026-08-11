# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the ``hunterx tools`` CLI command group (Sprint 031)."""

from __future__ import annotations

import json

from hunterx.cli.app import CliApplication


def _app() -> CliApplication:
    app = CliApplication()
    from hunterx.cli.commands import register_default_commands

    register_default_commands(app)
    return app


def _run(app: CliApplication, argv: list[str]) -> tuple[int, str]:
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = app.run(argv)
    return code, buffer.getvalue()


def test_tools_list_prints_catalog() -> None:
    app = _app()
    code, out = _run(app, ["tools", "list"])
    assert code == 0
    payload = json.loads(out)
    assert isinstance(payload, list)
    assert any(tool["tool_id"] == "subfinder" for tool in payload)


def test_tools_show_prints_knowledge_contract() -> None:
    app = _app()
    code, out = _run(app, ["tools", "show", "nuclei"])
    assert code == 0
    payload = json.loads(out)
    assert payload["tool_id"] == "nuclei"
    assert "knowledge" in payload


def test_tools_capabilities() -> None:
    app = _app()
    code, out = _run(app, ["tools", "capabilities", "ffuf"])
    assert code == 0
    payload = json.loads(out)
    assert "directory-discovery" in payload

    code, out = _run(app, ["tools", "capabilities"])
    assert code == 0
    assert isinstance(json.loads(out), list)


def test_tools_health_and_versions() -> None:
    app = _app()
    code, out = _run(app, ["tools", "health", "nmap"])
    assert code == 0
    payload = json.loads(out)
    assert payload["tool_id"] == "nmap"

    code, out = _run(app, ["tools", "versions", "nmap"])
    assert code == 0
    payload = json.loads(out)
    assert payload["tool_id"] == "nmap"


def test_tools_chain_plans_objective() -> None:
    app = _app()
    code, out = _run(app, ["tools", "chain", "Recon surface", "--capabilities", "subdomain-discovery,http-probing"])
    assert code == 0
    payload = json.loads(out)
    assert payload["objective"] == "Recon surface"
    assert payload["steps"]


def test_tools_recommend_returns_ranked_tools() -> None:
    app = _app()
    code, out = _run(app, ["tools", "recommend", "port-scanning"])
    assert code == 0
    payload = json.loads(out)
    assert payload
    assert payload[0]["kind"] == "best"


def test_tools_parse_offline_replay() -> None:
    app = _app()
    code, out = _run(app, ["tools", "parse", "subfinder", "--raw", '{"host": "api.example.com", "source": "crt.sh"}'])
    assert code == 0
    payload = json.loads(out)
    assert payload["tool_id"] == "subfinder"
    assert payload["count"] >= 1


def test_tools_normalize_offline() -> None:
    app = _app()
    records = json.dumps({"title": "x", "severity": "medium", "target": "t", "description": "d"})
    code, out = _run(app, ["tools", "normalize", "nuclei", "--records", records])
    assert code == 0
    payload = json.loads(out)
    assert payload["counts"]["findings"] == 1


def test_tools_execute_returns_execution_id() -> None:
    app = _app()
    code, out = _run(app, ["tools", "execute", "javascript", "https://example.com"])
    assert code == 0
    payload = json.loads(out)
    assert "execution_id" in payload


def test_tools_show_unknown_tool_raises() -> None:
    app = _app()
    import pytest

    from hunterx.domain.exceptions import ToolNotFoundError

    with pytest.raises(ToolNotFoundError):
        app.run(["tools", "show", "definitely-missing-tool"])


def test_help_lists_tool_commands() -> None:
    app = _app()
    help_text = app.help_text()
    for name in (
        "tools list",
        "tools show",
        "tools capabilities",
        "tools health",
        "tools versions",
        "tools execute",
        "tools inspect-result",
        "tools parse",
        "tools normalize",
        "tools chain",
        "tools recommend",
    ):
        assert name in help_text, f"missing {name} in help"
