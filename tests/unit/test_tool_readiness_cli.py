# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""CLI tests for tool readiness commands.

Exercises the real ``hunterx tools check`` / ``hunterx tools install`` /
``hunterx install`` / ``hunterx hunt`` command paths with a stubbed readiness
service and a deterministic execution engine. No real package is installed.
"""

from __future__ import annotations

import json

import pytest

from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.platform import build_platform
from hunterx.tools.readiness.models import (
    CapabilityLevel,
    CapabilityReadiness,
    InstallOutcome,
    PreflightResult,
    PreflightStatus,
    ReadinessReport,
    ToolReadiness,
    ToolReadinessStatus,
)
from tests.framework.fakes import FakeExecutionEngine

_TARGET = "https://juice-shop.herokuapp.com"

_DIMENSIONS = (
    "identity", "capability", "discovery", "installation", "verification",
    "version", "commands", "arguments", "invocation", "output", "parser",
    "platform", "safety",
)

_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.target"}]},
    "nmap": {"ports": [80, 443]},
}


class FakeReadinessService:
    """Readiness double with deterministic check/install/preflight behavior."""

    def __init__(self, *, blocked: bool = False) -> None:
        self._blocked = blocked
        self.install_calls: list[dict[str, object]] = []

    def check(self, tool_ids=None, *, sync_engine=True):  # noqa: ANN001
        tools = [
            ToolReadiness(
                tool_id="nmap",
                status=ToolReadinessStatus.AVAILABLE,
                version="7.94",
                path="/usr/bin/nmap",
            ),
            ToolReadiness(tool_id="nuclei", status=ToolReadinessStatus.MISSING),
        ]
        capabilities = [
            CapabilityReadiness(
                capability="port_discovery",
                level=CapabilityLevel.REQUIRED,
                providers=("nmap",),
                available=("nmap",),
                missing=(),
            )
        ]
        return ReadinessReport(
            platform={"os": "linux", "distro": "ubuntu", "supported": True},
            tools=tools,
            capabilities=capabilities,
            summary={
                "total": 2,
                "available": 1,
                "missing": 1,
                "broken": 0,
                "outdated": 0,
                "unsupported": 0,
                "capabilities_ready": 1,
                "capabilities_missing": 0,
            },
        )

    def install(self, tool_ids=None, *, profile="", verify=True):  # noqa: ANN001
        if profile and profile not in self.profiles():
            raise ValueError(
                f"unknown install profile '{profile}' (choose from {', '.join(self.profiles())})"
            )
        self.install_calls.append({"tool_ids": tool_ids, "profile": profile})
        return [
            InstallOutcome(
                tool_id="sqlmap",
                success=True,
                status=ToolReadinessStatus.AVAILABLE,
                version="1.10.8",
                skipped=False,
            )
        ]

    def profiles(self):
        return ("minimal", "recon", "web", "network", "vulnerability", "full")

    def profile_tools(self, profile: str):
        return ("sqlmap",)

    def preflight(self, capabilities, *, mission_id="", auto_provision=True):  # noqa: ANN001
        if self._blocked:
            return PreflightResult(
                status=PreflightStatus.BLOCKED,
                mission_id=mission_id,
                required_missing=("subdomain_enumeration",),
                missing_tools=("subfinder",),
                blocked_reason="mission blocked: required capabilities without an available provider",
            )
        return PreflightResult(status=PreflightStatus.PASS, mission_id=mission_id)

    def audit(self, tool_ids=None, *, refresh_availability=True):  # noqa: ANN001
        from hunterx.tools.readiness.audit import (
            IntegrationAuditReport,
            IntegrationLevel,
            ToolAudit,
        )

        return IntegrationAuditReport(
            audits=[
                ToolAudit(
                    tool_id="nmap",
                    dimensions={d: True for d in _DIMENSIONS},
                    level=IntegrationLevel.FULLY_INTEGRATED,
                    runtime=True,
                ),
                ToolAudit(
                    tool_id="kiterunner",
                    dimensions={d: (d not in ("installation", "verification")) for d in _DIMENSIONS},
                    missing=("installation", "verification"),
                    level=IntegrationLevel.DISCOVERABLE,
                    runtime=True,
                ),
            ],
            summary={
                "fully_integrated": 1,
                "discoverable": 1,
                "known": 0,
                "unknown": 0,
                "verified": 0,
                "invokable": 0,
                "parsable": 0,
                "installable": 0,
            },
        )

    def definition(self, tool_id: str):
        from hunterx.tools.readiness.models import ToolDefinition

        return ToolDefinition(tool_id=tool_id, name=tool_id)


@pytest.fixture()
def app():
    platform = build_platform()
    app = CliApplication()
    register_default_commands(app, platform)
    return app, platform


class TestToolsCheck:
    def test_check_renders_table(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        assert app_instance.run(["tools", "check"]) == 0
        output = capsys.readouterr().out

        assert "Tool" in output and "Status" in output and "Version" in output and "Path" in output
        assert "NMAP" in output.upper() or "AVAILABLE" in output.upper()
        assert "MISSING" in output.upper()
        assert "Capability" in output and "port_discovery" in output

    def test_check_json(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        assert app_instance.run(["tools", "check", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert payload["summary"]["total"] == 2
        assert payload["tools"][0]["tool_id"] == "nmap"
        assert payload["tools"][0]["status"] == "available"


class TestToolsInstall:
    def test_install_by_tool_id(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        service = FakeReadinessService()
        platform.tool_readiness_service = service  # type: ignore[assignment]

        assert app_instance.run(["tools", "install", "sqlmap"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert payload[0]["tool_id"] == "sqlmap"
        assert payload[0]["success"] is True
        assert service.install_calls[0]["tool_ids"] == ["sqlmap"]

    def test_install_by_profile(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        service = FakeReadinessService()
        platform.tool_readiness_service = service  # type: ignore[assignment]

        assert app_instance.run(["tools", "install", "--profile", "recon"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert service.install_calls[0]["profile"] == "recon"
        assert payload[0]["success"] is True

    def test_install_rejects_unknown_profile(self, app) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        with pytest.raises(SystemExit):
            app_instance.run(["tools", "install", "--profile", "does-not-exist"])


class TestInstall:
    def test_install_establishes_base_environment(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        assert app_instance.run(["install"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert payload["action"] == "install"
        assert payload["profile"] == "minimal"
        assert payload["status"] in ("complete", "degraded")
        assert payload["outcomes"][0]["status"] == "available"

    def test_install_with_profile(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        assert app_instance.run(["install", "--profile", "recon"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert payload["profile"] == "recon"
        assert payload["status"] in ("complete", "degraded")


class TestToolsAudit:
    def test_audit_renders_maturity_table(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        assert app_instance.run(["tools", "audit"]) == 0
        output = capsys.readouterr().out

        assert "Tool" in output and "Level" in output
        assert "FULLY_INTEGRATED" in output.upper()
        assert "DISCOVERABLE" in output.upper()

    def test_audit_json(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        platform.tool_readiness_service = FakeReadinessService()  # type: ignore[assignment]

        assert app_instance.run(["tools", "audit", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)

        assert payload["summary"]["fully_integrated"] == 1
        assert payload["audits"][0]["tool_id"] == "nmap"
        assert payload["audits"][0]["level"] == "fully_integrated"


class TestHuntBlockedSurface:
    def test_hunt_reports_blocked_with_reason(self, app, capsys: pytest.CaptureFixture[str]) -> None:
        app_instance, platform = app
        fake = FakeExecutionEngine(outputs=dict(_OUTPUTS))
        platform.mission_execution_service._engine = fake  # noqa: SLF001
        platform.mission_execution_service._readiness = FakeReadinessService(blocked=True)  # noqa: SLF001

        assert app_instance.run(["hunt", "full_security_assessment", _TARGET]) == 0
        overview = json.loads(capsys.readouterr().out)

        assert overview["status"] == "blocked"
        assert "blocked" in overview["reason"]
        assert overview["missing_tools"] == ["subfinder"]
        assert not fake.calls, "no tool may execute when the preflight blocks"
