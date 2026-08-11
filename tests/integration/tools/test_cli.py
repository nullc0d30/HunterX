# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the ``hunterx tools`` command group (Sprint 034.5)."""

from __future__ import annotations

import json

from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands


def _app() -> CliApplication:
    app = CliApplication()
    register_default_commands(app)
    return app


def _run(app: CliApplication, argv: list[str]) -> tuple[int, str]:
    import io
    from contextlib import redirect_stdout

    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = app.run(argv)
    return code, buffer.getvalue()


class TestToolsContractCommand:
    def test_tools_contract_prints_full_contract(self):
        app = _app()
        code, out = _run(app, ["tools", "contract", "nmap"])
        assert code == 0
        payload = json.loads(out)
        for key in (
            "identity", "version", "category", "capabilities", "requirements",
            "input_schema", "argument_builder", "scope_model", "execution_profile",
            "timeout", "resource_limits", "output_formats", "exit_code_mapping",
            "parser", "normalizer", "artifact_handling", "error_mapping",
            "retry_policy", "evidence_mapping", "downstream_capabilities",
        ):
            assert payload.get(key) not in (None, "", [], {}), f"missing {key}"

    def test_tools_contracts_lists_every_tool(self):
        app = _app()
        code, out = _run(app, ["tools", "contracts"])
        assert code == 0
        payload = json.loads(out)
        ids = {item["tool_id"] for item in payload}
        assert {"subfinder", "sqlmap", "nuclei", "gitleaks"} <= ids

    def test_tools_chain_plans_dependencies(self):
        app = _app()
        code, out = _run(app, ["tools", "chain", "recon-web", "--capabilities", "subdomain-discovery,http-probing"])
        assert code == 0
        payload = json.loads(out)
        assert payload["dependencies"]
        assert len(payload["steps"]) == 2
