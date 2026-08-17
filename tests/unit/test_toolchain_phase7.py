# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 7 — toolchain readiness + arjun runtime repair regression tests.

Proves:
- profile-required tools (katana, nuclei) are provisioned when absent;
- optional tools stay optional when not required by the selected profile;
- the arjun adapter builds a valid command and reads its JSON report;
- readiness does not report a broken arjun invocation as healthy.
"""

from __future__ import annotations

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.parameter.adapters import ArjunAdapter
from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.models import (
    InstallOutcome,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.service import ToolReadinessService
from tests.framework.readiness import linux_platform, tip_with

_PROFILE_TOOLS = ("httpx", "katana", "ffuf", "arjun", "nuclei")


class MappingDiscovery:
    """Discovery double whose per-tool status is controllable."""

    def __init__(self, statuses: dict[str, ToolReadinessStatus]) -> None:
        self._statuses = statuses
        self.marked: list[str] = []

    def probe(self, definition, platform):  # noqa: ANN001
        return ToolReadiness(
            tool_id=definition.tool_id,
            status=self._statuses.get(definition.tool_id, ToolReadinessStatus.MISSING),
            version="1.2.3"
            if self._statuses.get(definition.tool_id) is ToolReadinessStatus.AVAILABLE
            else "",
            definition=definition,
            platform=platform.os,
        )

    def discover(self, definitions, platform):  # noqa: ANN001
        return [self.probe(definition, platform) for definition in definitions]

    def mark_installed(self, tool_id: str, version: str = "") -> None:
        self.marked.append(tool_id)


class StubProvisioner:
    """Provisioner double that always succeeds or always fails."""

    def __init__(self, *, succeed: bool = True) -> None:
        self._succeed = succeed
        self.install_calls: list[str] = []

    def install(self, definition, *, verify=True):  # noqa: ANN001
        self.install_calls.append(definition.tool_id)
        if self._succeed:
            return InstallOutcome(
                tool_id=definition.tool_id,
                success=True,
                status=ToolReadinessStatus.AVAILABLE,
                version="9.9.9",
            )
        return InstallOutcome(
            tool_id=definition.tool_id,
            success=False,
            status=ToolReadinessStatus.PROVISIONING_FAILED,
            error="go: command not found",
        )


_TOOL_IDS = [
    "subfinder", "amass", "assetfinder", "dnsx", "dnspython", "nmap", "rustscan",
    "httpx", "katana", "nuclei", "sqlmap", "proof-replay", "ffuf", "gobuster", "arjun",
]

_ALL_AVAILABLE: dict[str, ToolReadinessStatus] = {
    "subfinder": ToolReadinessStatus.AVAILABLE,
    "amass": ToolReadinessStatus.AVAILABLE,
    "assetfinder": ToolReadinessStatus.AVAILABLE,
    "dnsx": ToolReadinessStatus.AVAILABLE,
    "dnspython": ToolReadinessStatus.AVAILABLE,
    "nmap": ToolReadinessStatus.AVAILABLE,
    "rustscan": ToolReadinessStatus.AVAILABLE,
    "httpx": ToolReadinessStatus.AVAILABLE,
    "katana": ToolReadinessStatus.AVAILABLE,
    "nuclei": ToolReadinessStatus.AVAILABLE,
    "sqlmap": ToolReadinessStatus.AVAILABLE,
    "proof-replay": ToolReadinessStatus.AVAILABLE,
    "ffuf": ToolReadinessStatus.AVAILABLE,
    "gobuster": ToolReadinessStatus.AVAILABLE,
    "arjun": ToolReadinessStatus.AVAILABLE,
}


def _service(statuses: dict[str, ToolReadinessStatus], *, provisioner: StubProvisioner | None = None):
    platform = linux_platform()
    tip = tip_with(_TOOL_IDS)
    builder = ToolDefinitionBuilder(tip, platform)
    return ToolReadinessService(
        tip=tip,
        engine=None,
        platform=platform,
        definitions=builder,
        discovery=MappingDiscovery(statuses),
        provisioner=provisioner,
    )


class TestProfileProvisioning:
    def test_required_profile_provisions_katana_when_absent(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        statuses["katana"] = ToolReadinessStatus.MISSING
        statuses["nuclei"] = ToolReadinessStatus.MISSING
        statuses["arjun"] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=True)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(
            ["endpoint_enumeration", "content_discovery", "parameter_discovery", "vulnerability_scanning"],
            profile_tools=_PROFILE_TOOLS,
            auto_provision=True,
        )

        assert preflight.provision_attempted is True
        assert "katana" in preflight.provisioned, preflight.provisioned
        assert "katana" in provisioner.install_calls

    def test_required_profile_provisions_nuclei_when_absent(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        statuses["nuclei"] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=True)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(
            ["vulnerability_scanning"],
            profile_tools=_PROFILE_TOOLS,
            auto_provision=True,
        )

        assert "nuclei" in preflight.provisioned, preflight.provisioned
        assert "nuclei" in provisioner.install_calls

    def test_optional_tool_not_in_profile_stays_optional(self) -> None:
        # gobuster is not part of the bug-bounty profile tool set; content
        # discovery is still covered by ffuf, so gobuster must NOT be
        # provisioned and the mission only degrades for it.
        statuses = dict(_ALL_AVAILABLE)
        statuses["gobuster"] = ToolReadinessStatus.MISSING
        statuses["katana"] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=True)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(
            ["endpoint_enumeration", "content_discovery"],
            profile_tools=_PROFILE_TOOLS,
            auto_provision=True,
        )

        assert "katana" in preflight.provisioned
        assert "gobuster" not in preflight.provisioned
        assert "gobuster" not in provisioner.install_calls
        assert preflight.may_execute

    def test_profile_provisioning_failure_degrades_not_blocks(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        statuses["nuclei"] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=False)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(
            ["vulnerability_scanning"],
            profile_tools=_PROFILE_TOOLS,
            auto_provision=True,
        )

        assert "nuclei" in preflight.provision_failures
        assert preflight.may_execute  # recommended capability -> degrade, not block

    def test_no_auto_provision_skips_profile_tools(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        statuses["katana"] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=True)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(
            ["endpoint_enumeration"],
            profile_tools=_PROFILE_TOOLS,
            auto_provision=False,
        )

        assert preflight.provision_attempted is False
        assert "katana" not in provisioner.install_calls

    def test_profile_tools_accessor(self) -> None:
        service = _service(dict(_ALL_AVAILABLE))
        assert "katana" in service.mission_profile_tools("bug_bounty_assessment")
        assert "nuclei" in service.mission_profile_tools("bug_bounty_assessment")
        assert service.mission_profile_tools("unknown_objective") == ()


class TestArjunCommand:
    def test_adapter_builds_valid_command(self) -> None:
        context = ExecutionContext(tool_id="arjun", target="http://127.0.0.1:3010/rest/products/search")
        argv = ArjunAdapter().build_argv(context)

        assert argv[0] == "arjun"
        assert "-u" in argv
        assert "-oJ" in argv
        index = argv.index("-oJ")
        json_arg = argv[index + 1]
        # ``-oJ`` must carry a file argument (not the next flag) or arjun
        # exits with an argparse usage error.
        assert not json_arg.startswith("-")
        assert json_arg.endswith(".json")
        assert "-q" in argv

    def test_adapter_is_invocation_verifiable(self) -> None:
        assert ArjunAdapter.INVOCATION_VERIFIABLE is True


class TestInvocationHealth:
    def test_broken_invocation_detected(self) -> None:
        service = ToolReadinessService.__new__(ToolReadinessService)  # type: ignore[call-arg]

        class _BrokenArjun(ArjunAdapter):
            def build_argv(self, context):  # noqa: ANN001
                return ["arjun", "-u", context.target, "-oJ", "-q"]

        reason = service._invocation_is_broken(_BrokenArjun(), "arjun")  # noqa: SLF001
        assert reason is not None
        assert "argument-parsing error" in reason

    def test_fixed_invocation_not_broken(self) -> None:
        service = ToolReadinessService.__new__(ToolReadinessService)  # type: ignore[call-arg]
        reason = service._invocation_is_broken(ArjunAdapter(), "arjun")  # noqa: SLF001
        assert reason is None
