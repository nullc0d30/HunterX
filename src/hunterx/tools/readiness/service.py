# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Readiness application facade.

The single use-case layer the CLI, API and mission preflight call to:

- build machine-readable tool definitions (TIP knowledge + trusted manifest);
- discover/verify installed tools (``check``);
- compute per-capability coverage;
- provision missing tools through trusted static methods (``install``);
- resolve mission capability requirements and produce preflight verdicts.

The service reuses the Tool Integration SDK engine: discovered tools are
recorded on the engine so the SDK health checker and the mission execution
pipeline agree on what is actually runnable.
"""

from __future__ import annotations

import contextlib
from typing import Any

from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.readiness.audit import IntegrationAuditReport, ToolIntegrationAuditor
from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.discovery import (
    ToolDiscovery,
    ensure_user_script_paths,
)
from hunterx.tools.readiness.models import (
    CapabilityLevel,
    CapabilityReadiness,
    InstallOutcome,
    InstallProgress,
    PreflightResult,
    ReadinessReport,
    ToolDefinition,
    ToolInventory,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.platform import PlatformDetector, PlatformInfo
from hunterx.tools.readiness.preflight import MissionPreflight
from hunterx.tools.readiness.provisioner import ToolProvisioner


class ToolReadinessService:
    """Facade over the Tool Readiness subsystem.

    Args:
        tip: the Tool Intelligence API (authoritative tool knowledge).
        engine: optional Tool Integration SDK execution engine (readiness is
            synced onto it so mission execution health checks agree).
        platform: optional detected platform; defaults to live detection.
        definitions: optional definition builder (auto-built when omitted).
        discovery: optional discovery probe (auto-built when omitted).
        provisioner: optional provisioner (auto-built when omitted).
        preflight: optional preflight engine (auto-built when omitted).

    """

    def __init__(
        self,
        *,
        tip: ToolIntelligenceAPI,
        engine: Any | None = None,
        platform: PlatformInfo | None = None,
        definitions: ToolDefinitionBuilder | None = None,
        discovery: ToolDiscovery | None = None,
        provisioner: ToolProvisioner | None = None,
        preflight: MissionPreflight | None = None,
    ) -> None:
        self._tip = tip
        self._engine = engine
        self._platform = platform or PlatformDetector().detect()
        self._definitions = definitions or ToolDefinitionBuilder(tip, self._platform)
        self._discovery = discovery or ToolDiscovery(engine)
        self._provisioner = provisioner or ToolProvisioner(self._discovery, self._platform)
        self._preflight = preflight or MissionPreflight(
            capability_providers=self._definitions.capability_providers(),
            capability_levels=self._definitions.capability_levels(),
        )
        self._auditor = ToolIntegrationAuditor(
            tip=tip,
            definitions=self._definitions,
            engine=engine,
        )
        # Make provisioned console scripts (pip --user / pipx) discoverable and
        # runnable in this process.
        ensure_user_script_paths()

    # -- catalog -----------------------------------------------------------

    def definitions(self, tool_ids: list[str] | None = None) -> list[ToolDefinition]:
        """Return the machine-readable definitions (optionally filtered)."""
        all_definitions = self._definitions.build_all()
        if not tool_ids:
            return all_definitions
        wanted = set(tool_ids)
        return [definition for definition in all_definitions if definition.tool_id in wanted]

    def definition(self, tool_id: str) -> ToolDefinition | None:
        """Return the definition for ``tool_id`` or ``None``."""
        return self._definitions.build(tool_id)

    def profiles(self) -> tuple[str, ...]:
        """Return the canonical install profile names."""
        return self._definitions.profiles()

    def profile_tools(self, profile: str) -> tuple[str, ...]:
        """Return the tool ids included in ``profile`` (empty when unknown)."""
        return self._definitions.profile_tools(profile)

    # -- discovery / check -------------------------------------------------

    def check(
        self,
        tool_ids: list[str] | None = None,
        *,
        sync_engine: bool = True,
    ) -> ReadinessReport:
        """Probe the current environment and return the readiness report.

        When ``sync_engine`` is set, tools discovered as available are
        recorded on the Tool Integration SDK engine so its health checker
        agrees with the readiness verdict.
        """
        definitions = self.definitions(tool_ids)
        readiness = self._discovery.discover(definitions, self._platform)
        if sync_engine:
            for verdict in readiness:
                if verdict.status is ToolReadinessStatus.AVAILABLE:
                    self._discovery.mark_installed(verdict.tool_id, verdict.version)
                    self._sync_tip_state(verdict.tool_id, verdict.version)
        by_tool = {verdict.tool_id: verdict for verdict in readiness}
        capabilities = self.capability_coverage(readiness=by_tool)
        summary = {
            "total": len(readiness),
            "available": sum(1 for v in readiness if v.status is ToolReadinessStatus.AVAILABLE),
            "missing": sum(1 for v in readiness if v.status is ToolReadinessStatus.MISSING),
            "broken": sum(1 for v in readiness if v.status is ToolReadinessStatus.BROKEN),
            "shadowed": sum(1 for v in readiness if v.status is ToolReadinessStatus.SHADOWED),
            "outdated": sum(1 for v in readiness if v.status is ToolReadinessStatus.OUTDATED),
            "unsupported": sum(1 for v in readiness if v.status is ToolReadinessStatus.UNSUPPORTED),
            "manual_only": sum(1 for v in readiness if v.status is ToolReadinessStatus.MANUAL_ONLY),
            "not_cli": sum(1 for v in readiness if v.status is ToolReadinessStatus.NOT_CLI),
            "deprecated": sum(1 for v in readiness if v.status is ToolReadinessStatus.DEPRECATED),
            "platform_unavailable": sum(
                1 for v in readiness if v.status is ToolReadinessStatus.PLATFORM_UNAVAILABLE
            ),
            "provisioning_failed": sum(
                1 for v in readiness if v.status is ToolReadinessStatus.PROVISIONING_FAILED
            ),
            "capabilities_ready": sum(1 for c in capabilities if c.ready),
            "capabilities_missing": sum(1 for c in capabilities if not c.ready),
        }
        return ReadinessReport(
            platform=self._platform.to_dict(),
            tools=readiness,
            capabilities=capabilities,
            summary=summary,
        )

    def probe(self, tool_id: str) -> ToolReadiness:
        """Probe a single tool and return its readiness verdict."""
        definition = self._definitions.build(tool_id)
        if definition is None:
            return ToolReadiness(tool_id=tool_id, status=ToolReadinessStatus.UNKNOWN, error=f"unknown tool '{tool_id}'")
        verdict = self._discovery.probe(definition, self._platform)
        if verdict.status is ToolReadinessStatus.AVAILABLE:
            self._discovery.mark_installed(tool_id, verdict.version)
        return verdict

    # -- capability coverage ------------------------------------------------

    def capability_coverage(
        self,
        capabilities: list[str] | None = None,
        *,
        readiness: dict[str, ToolReadiness] | None = None,
    ) -> list[CapabilityReadiness]:
        """Return per-capability readiness.

        A capability is ``ready`` when at least one registered provider is
        currently available. ``capabilities`` filters to a subset; when
        omitted the full planner capability catalog is evaluated.
        """
        if readiness is None:
            readiness = {
                verdict.tool_id: verdict
                for verdict in self._discovery.discover(self.definitions(), self._platform)
            }
        providers_map = self._definitions.capability_providers()
        levels = self._definitions.capability_levels()
        wanted = capabilities or list(providers_map)
        coverage: list[CapabilityReadiness] = []
        for capability in wanted:
            providers = providers_map.get(capability, ())
            available = tuple(
                tool_id
                for tool_id in providers
                if readiness.get(tool_id) is not None
                and readiness[tool_id].status is ToolReadinessStatus.AVAILABLE
            )
            missing = tuple(tool_id for tool_id in providers if tool_id not in available)
            coverage.append(
                CapabilityReadiness(
                    capability=capability,
                    level=levels.get(capability, CapabilityLevel.REQUIRED),
                    providers=providers,
                    available=available,
                    missing=missing,
                )
            )
        return coverage

    def available_tools(self) -> list[str]:
        """Return the tool ids currently available on the environment."""
        return [
            verdict.tool_id
            for verdict in self._discovery.discover(self.definitions(), self._platform)
            if verdict.status is ToolReadinessStatus.AVAILABLE
        ]

    # -- provisioning ------------------------------------------------------

    def install(
        self,
        tool_ids: list[str] | None = None,
        *,
        profile: str = "",
        verify: bool = True,
        observer: Any | None = None,
        state: Any | None = None,
    ) -> list[InstallOutcome]:
        """Provision missing tools and return the per-tool outcomes.

        ``tool_ids`` takes precedence; when empty, ``profile`` selects the
        profile's tools. An empty both defaults to the ``minimal`` profile
        (base HunterX environment — no external installs).

        ``observer`` (optional) receives :class:`InstallProgress` events
        before and after each tool so a UI can render live ``[N/M] tool ✓``
        lines. ``state`` (optional) is an :class:`InstallationState` that is
        updated with per-tool results and persisted by the caller for resume
        support.
        """
        targets = self._resolve_targets(tool_ids, profile)
        total = len(targets)
        outcomes: list[InstallOutcome] = []
        for index, tool_id in enumerate(targets, start=1):
            if state is not None:
                state.mark_tool_started(tool_id)
                state.persist()
            if observer is not None:
                observer(
                    InstallProgress(
                        index=index,
                        total=total,
                        tool_id=tool_id,
                        phase="start",
                    )
                )
            definition = self._definitions.build(tool_id)
            if definition is None:
                outcome = InstallOutcome(tool_id=tool_id, success=False, error=f"unknown tool '{tool_id}'")
            else:
                try:
                    outcome = self._provisioner.install(definition, verify=verify)
                except KeyboardInterrupt:
                    if state is not None:
                        state.mark_interrupted(f"interrupted while installing '{tool_id}'")
                        state.persist()
                    raise
            outcomes.append(outcome)
            if state is not None:
                state.record_tool(outcome)
                state.persist()
            if observer is not None:
                observer(
                    InstallProgress(
                        index=index,
                        total=total,
                        tool_id=tool_id,
                        phase="done",
                        outcome=outcome,
                    )
                )
        return outcomes

    def inventory(self) -> ToolInventory:
        """Return the grouped tool inventory (available/missing/broken/...)."""
        return ToolInventory.from_report(self.check())

    def _sync_tip_state(self, tool_id: str, version: str = "") -> None:
        """Record a discovered-available tool on the TIP lifecycle.

        The TIP selection engine (``tools chain`` / planner) only proposes
        tools whose lifecycle state is ``AVAILABLE``. Propagating the
        readiness verdict keeps the TIP planner and the readiness layer in
        agreement so the planner never proposes an unexecutable provider.
        """
        tip = self._tip
        if tip is None:
            return
        with contextlib.suppress(Exception):  # best-effort state propagation
            if not tip.is_usable(tool_id):
                if version:
                    tip.install(tool_id, version=version)
                else:
                    tip.install(tool_id)
                tip.verify(tool_id, ok=True)
                tip.make_available(tool_id)

    def _resolve_targets(self, tool_ids: list[str] | None, profile: str) -> list[str]:
        if tool_ids:
            return list(dict.fromkeys(tool_ids))
        if profile:
            if profile not in self._definitions.profiles():
                raise ValueError(
                    f"unknown install profile '{profile}' (choose from {', '.join(self._definitions.profiles())})"
                )
            return list(self._definitions.profile_tools(profile))
        return list(self._definitions.profile_tools("minimal"))

    # -- mission preflight --------------------------------------------------

    def resolve_required_capabilities(self, capabilities: list[str]) -> dict[str, CapabilityLevel]:
        """Return the importance level for each mission capability."""
        return self._preflight.levels_for(capabilities)

    def preflight(
        self,
        capabilities: list[str],
        *,
        mission_id: str = "",
        auto_provision: bool = True,
    ) -> PreflightResult:
        """Compute the mission preflight verdict for ``capabilities``.

        A mission whose required capabilities have no available provider
        returns a ``BLOCKED`` verdict (or, when ``auto_provision`` succeeds,
        a ``PASS``/``DEGRADED`` verdict). Missing recommended/optional
        capabilities produce a ``DEGRADED`` verdict — the mission may run
        with reduced coverage.
        """
        return self._preflight.run(
            self,
            capabilities,
            mission_id=mission_id,
            auto_provision=auto_provision,
            provisioner=self._provisioner,
        )

    # -- integration audit --------------------------------------------------

    def audit(
        self,
        tool_ids: list[str] | None = None,
        *,
        refresh_availability: bool = True,
    ) -> IntegrationAuditReport:
        """Return the integration-maturity audit for the claimed toolchain.

        ``refresh_availability`` re-probes the environment so the audit carries
        live runtime state (``available``) alongside the knowledge dimensions.
        """
        if refresh_availability:
            report = self.check()
            self._auditor._availability = {  # noqa: SLF001  # auditor is owned by the service
                verdict.tool_id: verdict.status is ToolReadinessStatus.AVAILABLE
                for verdict in report.tools
            }
        return self._auditor.audit(tool_ids)


__all__ = ["ToolReadinessService"]
