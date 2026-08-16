# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Toolchain completion & verification tests.

Covers the CLI-toolchain acceptance gate:

- the supported CLI catalog is complete (every manifest tool gets a definition,
  never an unexplained gap);
- GUI/daemon tools are classified ``not_cli`` and removed from capability
  providers;
- manual-only tools are classified precisely (never a vague ``missing``);
- ``hunterx tools check --json`` exposes the authoritative schema;
- generic executable shadowing is detected (a same-named unrelated CLI can
  never be reported as the security tool);
- deterministic install methods exist for the full catalog;
- neutral-CWD and clean-environment discovery work;
- the ``tools matrix`` command emits the final machine-readable inventory.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.manifest import (
    CAPABILITY_PROVIDERS,
    INSTALL_METHODS,
    TOOL_BINARY_SPECS,
    TOOL_CLASSIFICATIONS,
)
from hunterx.tools.readiness.models import ToolReadinessStatus
from tests.framework.readiness import (
    fake_executable,
    linux_platform,
    make_discovery,
    tip_with,
)

#: Every tool the CLI toolchain task requires to be handled explicitly.
_REQUIRED_TOOLS = [
    "findomain", "theharvester", "massdns", "rustscan", "linkfinder",
    "secretfinder", "xnlinkfinder", "paramspider", "kiterunner", "spiderfoot",
    "crt-sh", "unicornscan", "crobat", "gauplus", "feroxbuster", "graphqlmap",
    "jwt-tool", "openapi-parser", "postman-parser", "jsluice", "xssstrike",
    "ghauri", "tplmap", "sstimap", "xxeinjector", "trufflehog", "codeql",
    "zap", "netexec", "impacket", "enum4linux-ng", "trivy", "syft", "grype",
    "kube-bench", "metasploit", "searchsploit", "exploitdb",
]

_NOT_CLI_TOOLS = {"crt-sh", "spiderfoot", "openapi-parser", "postman-parser"}
_MANUAL_ONLY_TOOLS = {"kiterunner", "codeql", "xxeinjector"}


class TestCatalogCompleteness:
    def test_every_required_tool_has_a_definition(self) -> None:
        platform = linux_platform()
        tip = tip_with([])
        builder = ToolDefinitionBuilder(tip, platform)

        definitions = {definition.tool_id: definition for definition in builder.build_all()}

        for tool_id in _REQUIRED_TOOLS:
            assert tool_id in definitions, f"{tool_id} has no readiness definition"

    def test_every_required_tool_has_an_explicit_handling(self) -> None:
        # Every required tool is either installable (install methods) or has a
        # precise catalog classification. No tool may be left to fall through
        # to a vague unhandled state.
        for tool_id in _REQUIRED_TOOLS:
            assert (
                tool_id in INSTALL_METHODS
                or tool_id in TOOL_CLASSIFICATIONS
                or tool_id in TOOL_BINARY_SPECS
            ), f"{tool_id} is neither installable nor classified"

    def test_not_cli_tools_are_excluded_from_capability_providers(self) -> None:
        for capability, providers in CAPABILITY_PROVIDERS.items():
            for tool_id in _NOT_CLI_TOOLS:
                assert tool_id not in providers, (
                    f"{tool_id} (not CLI) must not be a provider of {capability}"
                )

    def test_certificate_enumeration_no_longer_depends_on_crt_sh(self) -> None:
        assert CAPABILITY_PROVIDERS["certificate_enumeration"] == ("findomain",)


class TestClassification:
    @pytest.mark.parametrize("tool_id", sorted(_NOT_CLI_TOOLS))
    def test_not_cli_tools_are_classified_not_cli(self, tool_id: str) -> None:
        platform = linux_platform()
        tip = tip_with([])
        definition = ToolDefinitionBuilder(tip, platform).build(tool_id)
        assert definition is not None
        assert definition.classification == "not_cli"
        assert not definition.cli_only

        verdict = make_discovery().probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.NOT_CLI
        assert verdict.reason

    @pytest.mark.parametrize("tool_id", sorted(_MANUAL_ONLY_TOOLS))
    def test_manual_only_tools_are_never_vague_missing(self, tool_id: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
        monkeypatch.setenv("PATH", str(tmp_path))
        for variable in ("HUNTERX_TOOL_BIN", "HUNTERX_DATA_DIR", "GOBIN", "GOPATH", "VIRTUAL_ENV"):
            monkeypatch.delenv(variable, raising=False)
        platform = linux_platform()
        definition = ToolDefinitionBuilder(tip_with([]), platform).build(tool_id)
        assert definition is not None
        assert definition.classification == "manual_only"
        assert definition.remediation

        verdict = make_discovery().probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.MANUAL_ONLY
        assert verdict.remediation
        assert verdict.health == "manual_only"


class TestVersionProbingResilience:
    def test_tolerates_shell_startup_noise_in_stderr(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
        # A tool whose probe emits an unrelated digit-bearing banner (plus any
        # shell boilerplate) must still validate the declared pattern.
        monkeypatch.setenv("PATH", str(tmp_path))
        for variable in ("HUNTERX_TOOL_BIN", "HUNTERX_DATA_DIR", "GOBIN", "GOPATH", "VIRTUAL_ENV"):
            monkeypatch.delenv(variable, raising=False)
        fake_executable(tmp_path, "nuclei", "[INF] Current nuclei version: v3.1.1")
        tip = tip_with(["nuclei"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("nuclei")

        verdict = make_discovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE
        assert verdict.version == "3.1.1"


class TestGenericCollision:
    def test_unrelated_python_cli_can_never_be_the_security_tool(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
        # Generic regression: a same-named unrelated CLI (e.g. a Python package
        # console script) shadows a security tool -> SHADOWED, never AVAILABLE.
        provider = tmp_path / "tools" / "bin"
        provider.mkdir(parents=True)
        fake_executable(provider, "nuclei", "[INF] Current nuclei version: v3.1.1")
        shadow = tmp_path / "venv" / "bin"
        shadow.mkdir(parents=True)
        fake_executable(shadow, "nuclei", "Usage: nuclei [OPTIONS] TARGET")
        os.environ["HUNTERX_TOOL_BIN"] = str(provider)
        monkeypatch.setenv("PATH", str(shadow) + os.pathsep + str(provider))
        tip = tip_with(["nuclei"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("nuclei")

        verdict = make_discovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.SHADOWED
        assert verdict.shadowed_by
        assert verdict.health == "shadowed"

    def test_preferred_provider_wins_over_runtime_cli(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
        # With the managed tools dir pinned first (launcher order), the Go
        # security binary is the provider and the runtime CLI is only a
        # reported collision.
        provider = tmp_path / "tools" / "bin"
        provider.mkdir(parents=True)
        fake_executable(provider, "nuclei", "[INF] Current nuclei version: v3.1.1")
        shadow = tmp_path / "venv" / "bin"
        shadow.mkdir(parents=True)
        fake_executable(shadow, "nuclei", "Usage: nuclei [OPTIONS] TARGET")
        os.environ["HUNTERX_TOOL_BIN"] = str(provider)
        monkeypatch.setenv("PATH", str(provider) + os.pathsep + str(shadow))
        tip = tip_with(["nuclei"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("nuclei")

        verdict = make_discovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE
        assert verdict.version == "3.1.1"
        assert verdict.shadowed_by


class TestInstallMethodsAdded:
    @pytest.mark.parametrize(
        "tool_id",
        [
            "crobat", "gauplus", "jsluice", "unicornscan", "trivy", "syft",
            "grype", "kube-bench", "netexec", "impacket", "enum4linux-ng",
            "linkfinder", "secretfinder", "xnlinkfinder", "jwt-tool",
        ],
    )
    def test_deterministic_install_method_declared(self, tool_id: str) -> None:
        assert tool_id in INSTALL_METHODS, f"{tool_id} needs an explicit install strategy"
        assert INSTALL_METHODS[tool_id], f"{tool_id} has an empty install strategy"


class TestJsonSchema:
    def test_tools_check_json_is_authoritative(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:  # noqa: ANN001, ANN003
        from tests.unit.test_tool_readiness_cli import FakeReadinessService

        platform = type(
            "P",
            (),
            {"tool_readiness_service": FakeReadinessService()},
        )()
        app = CliApplication()
        register_default_commands(app, platform)

        assert app.run(["tools", "check", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)

        tools = payload["tools"]
        assert tools, "the report must include tools"
        for field in (
            "name", "status", "executable", "resolved_path", "expected_identity",
            "version", "installation_method", "capabilities", "reason",
            "remediation", "platform", "shadowed_by", "health",
        ):
            assert field in tools[0], f"tools check --json is missing '{field}'"

    def test_verdict_to_dict_exposes_full_schema(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
        monkeypatch.setenv("PATH", str(tmp_path))
        for variable in ("HUNTERX_TOOL_BIN", "HUNTERX_DATA_DIR", "GOBIN", "GOPATH", "VIRTUAL_ENV"):
            monkeypatch.delenv(variable, raising=False)
        fake_executable(tmp_path, "nmap", "Nmap version 7.94 ( https://nmap.org )")
        tip = tip_with(["nmap"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("nmap")

        data = make_discovery().probe(definition, linux_platform()).to_dict()

        assert data["status"] == "available"
        assert data["health"] == "ok"
        assert data["name"] == "Nmap"
        assert data["resolved_path"]
        assert data["capabilities"] == ["port_discovery", "service_detection"]
        assert "installation_method" in data


class TestNeutralCwd:
    def test_discovery_from_neutral_cwd(self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: ANN001
        # Discovery must not depend on the process CWD: a clean temp directory
        # is the only PATH entry and the managed tool bin drives resolution.
        provider = tmp_path / "tools" / "bin"
        provider.mkdir(parents=True)
        fake_executable(provider, "nuclei", "[INF] Current nuclei version: v3.1.1")
        os.environ["HUNTERX_TOOL_BIN"] = str(provider)
        monkeypatch.setenv("PATH", str(provider))
        tip = tip_with(["nuclei"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("nuclei")

        verdict = make_discovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE

    def test_cli_runs_from_neutral_cwd(self, tmp_path: pathlib.Path) -> None:  # noqa: ANN001
        # ``hunterx tools check --json`` must resolve the catalog independent
        # of the caller's working directory.
        script = (
            "import sys, json; sys.path.insert(0, 'src'); "
            "from hunterx.cli.app import CliApplication; "
            "from hunterx.cli.commands import register_default_commands; "
            "from hunterx.platform import build_platform; "
            "app = CliApplication(); register_default_commands(app, build_platform()); "
            "assert app.run(['tools', 'check', '--json']) == 0"
        )
        root = pathlib.Path(__file__).resolve().parents[2]
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root / "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"


class TestToolsMatrix:
    def test_tools_matrix_json_emits_final_status(self, capsys: pytest.CaptureFixture[str]) -> None:  # noqa: ANN001, ANN003
        from tests.unit.test_tool_readiness_cli import FakeReadinessService

        service = FakeReadinessService()

        class _Engine:  # noqa: D101
            def adapter_for(self, tool_id: str):  # noqa: ANN001
                return object() if tool_id == "nmap" else None

        platform = type("P", (), {"tool_readiness_service": service})()
        platform.tool_readiness_service._engine = _Engine()  # type: ignore[attr-defined]  # test double
        app = CliApplication()
        register_default_commands(app, platform)

        assert app.run(["tools", "matrix", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)

        tools = payload["tools"]
        assert tools
        for field in (
            "tool", "cli_headless", "install_method", "installed", "resolved_path",
            "identity", "version", "health", "capabilities", "adapter",
            "execution", "final_status",
        ):
            assert field in tools[0], f"tools matrix is missing '{field}'"
        statuses = {row["final_status"] for row in tools}
        assert "READY" in statuses, "the available nmap tool must be READY"
