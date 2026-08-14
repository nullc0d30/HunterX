# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for tool readiness (capability coverage) and mission preflight.

Covers all-capabilities-available, required capability missing, optional
capability missing, alternative provider available, preflight provisioning
and provisioning-failure blocking.
"""

from __future__ import annotations

from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.models import (
    InstallOutcome,
    PreflightStatus,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.service import ToolReadinessService
from tests.framework.readiness import linux_platform, tip_with


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
    "httpx", "katana", "nuclei", "sqlmap", "proof-replay", "ffuf", "gobuster",
]

_DISCOVERY_CHAIN = [
    "subdomain_enumeration",
    "dns_enumeration",
    "port_discovery",
    "service_detection",
    "technology_fingerprint",
    "endpoint_enumeration",
]


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
}


class TestCapabilityCoverage:
    def test_all_capabilities_available(self) -> None:
        service = _service(dict(_ALL_AVAILABLE))
        coverage = {c.capability: c for c in service.capability_coverage(_DISCOVERY_CHAIN)}

        for capability in _DISCOVERY_CHAIN:
            assert coverage[capability].ready, capability

    def test_required_capability_missing(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        statuses["subfinder"] = ToolReadinessStatus.MISSING
        statuses["amass"] = ToolReadinessStatus.MISSING
        statuses["assetfinder"] = ToolReadinessStatus.MISSING
        service = _service(statuses)

        coverage = {c.capability: c for c in service.capability_coverage(_DISCOVERY_CHAIN)}

        assert coverage["subdomain_enumeration"].status == "missing"
        assert "subfinder" in coverage["subdomain_enumeration"].missing

    def test_optional_capability_missing_degrades(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        # certificate_enumeration providers are absent -> capability missing.
        service = _service(statuses)

        preflight = service.preflight(["certificate_enumeration"], auto_provision=False)

        assert preflight.status is PreflightStatus.DEGRADED
        assert preflight.may_execute

    def test_alternative_provider_available(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        statuses["nmap"] = ToolReadinessStatus.MISSING
        # rustscan provides port_discovery as an alternative.
        service = _service(statuses)

        coverage = {c.capability: c for c in service.capability_coverage(["port_discovery"])}

        assert coverage["port_discovery"].ready


class TestMissionPreflight:
    def test_preflight_passes_when_all_required_available(self) -> None:
        service = _service(dict(_ALL_AVAILABLE))

        preflight = service.preflight(_DISCOVERY_CHAIN, auto_provision=False)

        assert preflight.status is PreflightStatus.PASS
        assert preflight.required_missing == ()
        assert preflight.may_execute

    def test_preflight_blocks_when_required_capability_missing(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        for tool in ("subfinder", "amass", "assetfinder", "dnsx", "dnspython"):
            statuses[tool] = ToolReadinessStatus.MISSING
        service = _service(statuses)

        preflight = service.preflight(_DISCOVERY_CHAIN, auto_provision=False)

        assert preflight.status is PreflightStatus.BLOCKED
        assert "subdomain_enumeration" in preflight.required_missing
        assert preflight.missing_tools
        assert preflight.blocked_reason
        assert not preflight.may_execute

    def test_preflight_provisions_missing_when_supported(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        for tool in ("subfinder", "amass", "assetfinder"):
            statuses[tool] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=True)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(["subdomain_enumeration"], auto_provision=True)

        assert provisioner.install_calls, "provisioning must be attempted"
        assert preflight.status is PreflightStatus.PASS
        assert preflight.provision_attempted

    def test_preflight_blocks_when_provisioning_fails(self) -> None:
        statuses = dict(_ALL_AVAILABLE)
        for tool in ("subfinder", "amass", "assetfinder"):
            statuses[tool] = ToolReadinessStatus.MISSING
        provisioner = StubProvisioner(succeed=False)
        service = _service(statuses, provisioner=provisioner)

        preflight = service.preflight(["subdomain_enumeration"], auto_provision=True)

        assert preflight.status is PreflightStatus.BLOCKED
        assert preflight.provision_failures
        assert not preflight.may_execute

    def test_preflight_degrades_on_optional_gap(self) -> None:
        service = _service(dict(_ALL_AVAILABLE))

        preflight = service.preflight(["subdomain_enumeration", "certificate_enumeration"], auto_provision=False)

        assert preflight.status is PreflightStatus.DEGRADED
        assert preflight.optional_missing == ("certificate_enumeration",)
        assert preflight.may_execute
