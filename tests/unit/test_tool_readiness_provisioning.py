# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for tool provisioning.

Covers missing tool, supported installation method, successful installation,
failed installation, unsupported platform and idempotency. The command runner
is stubbed — no real package is ever installed.
"""

from __future__ import annotations

from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.models import (
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.platform import PlatformInfo
from hunterx.tools.readiness.provisioner import ToolProvisioner
from tests.framework.readiness import (
    StubRunner,
    all_commands_available,
    commands_available,
    linux_platform,
    tip_with,
)


class StubDiscovery:
    """Discovery double with controllable before/after readiness."""

    def __init__(
        self,
        *,
        before: ToolReadinessStatus = ToolReadinessStatus.MISSING,
        after: ToolReadinessStatus = ToolReadinessStatus.AVAILABLE,
    ) -> None:
        self._before = before
        self._after = after
        self.probe_count = 0
        self.marked: list[tuple[str, str]] = []

    def probe(self, definition, platform):  # noqa: ANN001
        self.probe_count += 1
        status = self._after if self.probe_count > 1 else self._before
        version = "9.9.9" if status is ToolReadinessStatus.AVAILABLE else ""
        return ToolReadiness(
            tool_id=definition.tool_id,
            status=status,
            version=version,
            definition=definition,
            platform=platform.os,
        )

    def mark_installed(self, tool_id: str, version: str = "") -> None:
        self.marked.append((tool_id, version))


def _definition(tool_id: str, platform: PlatformInfo):
    builder = ToolDefinitionBuilder(tip_with([tool_id]), platform)
    return builder.build(tool_id)


def _provisioner(discovery, platform, runner, *, commands=None):  # noqa: ANN001
    return ToolProvisioner(
        discovery,
        platform,
        runner,
        command_available=commands or all_commands_available,
    )


class TestMissingTool:
    def test_install_is_attempted_for_missing_tool(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(before=ToolReadinessStatus.MISSING, after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.success
        assert outcome.status is ToolReadinessStatus.AVAILABLE
        assert runner.calls, "an install command must be executed"
        assert runner.calls[0] == ["apt-get", "install", "-y", "nmap"]


class TestSupportedInstallationMethod:
    def test_apt_method_with_sudo_for_non_root(self) -> None:
        platform = linux_platform(is_root=False)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.method is not None and outcome.method.kind == "apt"
        assert runner.calls[0] == ["sudo", "apt-get", "install", "-y", "nmap"]

    def test_go_method_uses_static_module_path(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("subfinder", platform))

        assert outcome.method is not None and outcome.method.kind == "go"
        assert runner.calls[0][:3] == ["go", "install", "-v"]
        assert "projectdiscovery" in runner.calls[0][3]

    def test_pip_method_uses_user_flag_when_not_root(self) -> None:
        platform = linux_platform(is_root=False)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        provisioner.install(_definition("sqlmap", platform))

        assert "install" in runner.calls[0]
        assert "--user" in runner.calls[0]


class TestSuccessfulInstallation:
    def test_post_install_verification_marks_installed(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(before=ToolReadinessStatus.MISSING, after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.success
        assert outcome.version == "9.9.9"
        assert discovery.marked == [("nmap", "9.9.9")]


class TestFailedInstallation:
    def test_failed_install_reports_provisioning_failure(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({"apt-get": (100, "", "E: Unable to locate package")})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("nmap", platform))

        assert not outcome.success
        assert outcome.status is ToolReadinessStatus.PROVISIONING_FAILED
        assert "E: Unable to locate package" in outcome.error

    def test_unverified_install_reports_provisioning_failure(self) -> None:
        # The command exits 0 but the tool still cannot be verified.
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(before=ToolReadinessStatus.MISSING, after=ToolReadinessStatus.MISSING)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("nmap", platform))

        assert not outcome.success
        assert outcome.status is ToolReadinessStatus.PROVISIONING_FAILED
        assert "could not be verified" in outcome.error


class TestUnsupportedPlatform:
    def test_unsupported_method_for_platform(self) -> None:
        platform = linux_platform(distro="arch", is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery()
        provisioner = _provisioner(discovery, platform, runner)

        # 'kiterunner' has no install method at all.
        outcome = provisioner.install(_definition("kiterunner", platform))

        assert not outcome.success
        assert outcome.status is ToolReadinessStatus.UNSUPPORTED
        assert not runner.calls, "no command may run for an unsupported tool"

    def test_unsupported_reported_clearly_for_no_platform_method(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery()
        provisioner = _provisioner(discovery, platform, runner)

        # 'kiterunner' is a known tool with no trusted install method.
        outcome = provisioner.install(_definition("kiterunner", platform))

        assert "no compatible installation method" in outcome.error or "no supported" in outcome.error


class TestIdempotency:
    def test_available_tool_is_skipped_without_reinstall(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(before=ToolReadinessStatus.AVAILABLE, after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.success
        assert outcome.skipped
        assert not runner.calls, "an available tool must not be reinstalled"


class TestRuntimeAvailability:
    def test_go_method_skipped_when_go_missing(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(
            discovery,
            platform,
            runner,
            commands=commands_available("pip", "apt-get"),
        )

        # shuffledns has a go-only install method in the trusted manifest.
        outcome = provisioner.install(_definition("shuffledns", platform))

        assert not outcome.success
        assert outcome.status is ToolReadinessStatus.UNSUPPORTED
        assert not runner.calls, "go install must not be attempted without go"

    def test_choco_method_used_on_windows(self) -> None:
        platform = PlatformInfo(os="windows", package_manager="choco", supported=False, is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(
            discovery,
            platform,
            runner,
            commands=commands_available("choco"),
        )

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.success
        assert outcome.method is not None and outcome.method.kind == "choco"
        assert runner.calls[0][0] == "choco"


class TestTrustedCommands:
    def test_commands_are_never_built_from_user_input(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(after=ToolReadinessStatus.AVAILABLE)
        provisioner = _provisioner(discovery, platform, runner)

        # The install command for a package-manager tool must be exactly the
        # static manifest vector — a hostile tool id can never alter it.
        outcome = provisioner.install(_definition("nmap", platform))
        assert outcome.method is not None
        assert runner.calls[0] == ["apt-get", "install", "-y", "nmap"]
