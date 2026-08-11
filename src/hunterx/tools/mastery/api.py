# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Mastery API.

The Sprint 025 facade. Composes every mastery subsystem — master-profile
registry, relationship graph, playbook engine, mission-aware selector,
target history, coverage engine, dataset registry, version awareness,
parser regression and result replay — behind a single
:class:`~hunterx.domain.ports.tool_mastery.ToolMasteryPort` implementation.

The facade seeds itself from the canonical Sprint 025 data: the universal
arsenal (recon, web, analysis, enterprise, exploit tool specs), playbooks,
relationships and datasets. When given no external TIP, it builds and seeds
its own so selection is self-contained.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from hunterx.domain.ports.tool_mastery import ToolMasteryPort
from hunterx.domain.tool_mastery import (
    ToolCoverageReport,
    ToolDataset,
    ToolHistoryEntry,
    ToolHistoryStatus,
    ToolMasterProfile,
    ToolPlaybook,
    ToolPlaybookCategory,
    ToolRelationship,
    ToolSelectionDecision,
    ToolSupportLevel,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.mastery.coverage import ToolCoverageEngine
from hunterx.tools.mastery.dataset_data import register_default_datasets
from hunterx.tools.mastery.datasets import ToolDatasetRegistry
from hunterx.tools.mastery.history import ToolHistory
from hunterx.tools.mastery.playbook_data import register_default_playbooks
from hunterx.tools.mastery.playbooks import ToolPlaybookEngine
from hunterx.tools.mastery.registry import ToolMasteryRegistry
from hunterx.tools.mastery.regression import ParserRegressionEngine
from hunterx.tools.mastery.relationship_data import register_default_relationships
from hunterx.tools.mastery.relationships import ToolRelationshipGraph
from hunterx.tools.mastery.replay import ToolResultReplay
from hunterx.tools.mastery.selection import MissionAwareToolSelector
from hunterx.tools.mastery.specs import register_specs
from hunterx.tools.mastery.versioning import ToolVersionAwareness

if TYPE_CHECKING:
    from hunterx.tools.mastery.arsenal import UniversalSecurityArsenal


class ToolMasteryAPI(ToolMasteryPort):
    """Facade implementing :class:`ToolMasteryPort`.

    Usage::

        mastery = ToolMasteryAPI()
        profile = mastery.get_profile("nuclei")
        decision = mastery.select_best("xss-validation", mission_type="bug-bounty")
        report = mastery.coverage()
    """

    def __init__(
        self,
        tip: ToolIntelligenceAPI | None = None,
        registry: ToolMasteryRegistry | None = None,
        *,
        seed: bool = True,
    ) -> None:
        # ``tip`` is the TIP the mission-aware selector queries. When none is
        # given, the facade builds and seeds its own so selection works out of
        # the box against the full arsenal.
        self.tip = tip or ToolIntelligenceAPI()
        self.registry = registry or ToolMasteryRegistry()
        self.relationship_graph = ToolRelationshipGraph()
        self.playbook_engine = ToolPlaybookEngine()
        self.dataset_registry = ToolDatasetRegistry()
        self.history_engine = ToolHistory()
        self.versioning = ToolVersionAwareness(self.registry)
        self.regression = ParserRegressionEngine()
        self.replay = ToolResultReplay(self.regression)
        self.coverage_engine = ToolCoverageEngine(self.registry)
        self.selector = MissionAwareToolSelector(self.tip)
        if seed:
            self.seed_defaults()

    # -- seeding ----------------------------------------------------------

    def seed_defaults(self) -> None:
        """Load the canonical arsenal, playbooks, relationships and datasets.

        Idempotent: calling more than once re-registers (replaces) records.
        The master profiles are also registered into the internal TIP registry
        so mission-aware selection works against the arsenal.
        """
        from hunterx.tools.mastery.arsenal_analysis import (
            INJECTION_TOOLS,
            OOB_TOOLS,
            PROOF_REPLAY_TOOLS,
            PROXY_TOOLS,
            SAST_TOOLS,
            SECRETS_TOOLS,
            VULN_TOOLS,
        )
        from hunterx.tools.mastery.arsenal_enterprise import (
            CLOUD_TOOLS,
            COMPOSITION_TOOLS,
            CONTAINER_TOOLS,
            ENTERPRISE_TOOLS,
            SNMP_TOOLS,
        )
        from hunterx.tools.mastery.arsenal_exploit import (
            EXPLOIT_INTEL_TOOLS,
            EXPLOIT_TOOLS,
            KNOWLEDGE_SOURCE_TOOLS,
            PAYLOAD_KNOWLEDGE_TOOLS,
        )
        from hunterx.tools.mastery.arsenal_recon import (
            DNS_TOOLS,
            NETWORK_TOOLS,
            RECON_DNS_TOOLS,
        )
        from hunterx.tools.mastery.arsenal_web import (
            API_TOOLS,
            CONTENT_TOOLS,
            CRAWL_TOOLS,
            JAVASCRIPT_TOOLS,
            PARAMETER_TOOLS,
            WEB_TOOLS,
        )

        register_specs(
            self.registry,
            [
                *RECON_DNS_TOOLS,
                *DNS_TOOLS,
                *NETWORK_TOOLS,
                *WEB_TOOLS,
                *CRAWL_TOOLS,
                *CONTENT_TOOLS,
                *PARAMETER_TOOLS,
                *API_TOOLS,
                *JAVASCRIPT_TOOLS,
                *VULN_TOOLS,
                *INJECTION_TOOLS,
                *OOB_TOOLS,
                *SECRETS_TOOLS,
                *SAST_TOOLS,
                *PROXY_TOOLS,
                *PROOF_REPLAY_TOOLS,
                *ENTERPRISE_TOOLS,
                *SNMP_TOOLS,
                *CLOUD_TOOLS,
                *CONTAINER_TOOLS,
                *COMPOSITION_TOOLS,
                *EXPLOIT_TOOLS,
                *EXPLOIT_INTEL_TOOLS,
                *PAYLOAD_KNOWLEDGE_TOOLS,
                *KNOWLEDGE_SOURCE_TOOLS,
            ],
        )
        register_default_relationships(self.relationship_graph)
        register_default_playbooks(self.playbook_engine)
        register_default_datasets(self.dataset_registry)
        self.coverage_engine.set_capability_universe(list(self._capability_universe()))
        self.regression.register_builtin()
        self._seed_tip()

    def _seed_tip(self) -> None:
        """Register master profiles into the TIP registry.

        Tools already registered in the TIP (e.g. the richer platform records
        wired by the assembler) are left untouched — the mastery facade never
        clobbers existing TIP knowledge.
        """
        for profile in self.registry.list():
            if self.tip.get_tool(profile.tool_id) is not None:
                continue
            self.tip.register_tool(
                profile.metadata,
                knowledge=profile.knowledge,
                compatibility=profile.compatibility,
            )

    def _capability_universe(self) -> tuple[str, ...]:
        """Collect the canonical capability set across all registered profiles."""
        seen: list[str] = []
        for profile in self.registry.list():
            for capability in profile.capability_ids or profile.knowledge.capabilities:
                if capability not in seen:
                    seen.append(capability)
        return tuple(seen)

    # -- registry ---------------------------------------------------------

    def register_profile(self, profile: ToolMasterProfile) -> None:
        """Register (or replace) a master profile."""
        self.registry.register(profile)

    def get_profile(self, tool_id: str) -> ToolMasterProfile | None:
        """Return the master profile for ``tool_id`` or ``None``."""
        return self.registry.get(tool_id)

    def profiles(self) -> tuple[ToolMasterProfile, ...]:
        """Return every registered master profile."""
        return self.registry.list()

    def tool_ids(self) -> tuple[str, ...]:
        """Return every registered tool id."""
        return self.registry.tool_ids()

    def providers_of(self, capability_id: str) -> tuple[str, ...]:
        """Return tool ids that provide ``capability_id``."""
        return self.registry.providers_of(capability_id)

    def by_support_level(self, level: ToolSupportLevel) -> tuple[str, ...]:
        """Return tool ids classified at ``level``."""
        return self.registry.by_support_level(level)

    # -- consolidated contracts (Sprint 034.5) ------------------------------

    def contract(self, tool_id: str) -> dict[str, Any] | None:
        """Return the consolidated machine-readable contract for ``tool_id``."""
        from hunterx.tools.mastery.contract import build_contract

        profile = self.registry.get(tool_id)
        if profile is None:
            return None
        return build_contract(profile, self.relationship_graph).to_dict()

    def contracts(self) -> list[dict[str, Any]]:
        """Return the consolidated contract for every registered tool."""
        from hunterx.tools.mastery.contract import build_contract

        return [
            build_contract(profile, self.relationship_graph).to_dict()
            for profile in self.registry.list()
        ]

    # -- relationships ----------------------------------------------------

    def relationships(self, tool_id: str) -> list[ToolRelationship]:
        """Return every relationship edge touching ``tool_id``."""
        return self.relationship_graph.edges_for(tool_id)

    def next_tools(self, tool_id: str) -> list[str]:
        """Return the natural next tools after ``tool_id``."""
        return self.relationship_graph.next_tools(tool_id)

    def previous_tools(self, tool_id: str) -> list[str]:
        """Return the natural predecessor tools of ``tool_id``."""
        return self.relationship_graph.previous_tools(tool_id)

    def alternatives(self, tool_id: str) -> list[str]:
        """Return tools that REPLACE ``tool_id``."""
        return self.relationship_graph.alternatives(tool_id)

    def unknown_tool_refs(self) -> list[str]:
        """Return every relationship reference to an unregistered tool."""
        return self.relationship_graph.unknown_refs(list(self.registry.tool_ids()))

    # -- playbooks --------------------------------------------------------

    def playbooks(self) -> tuple[ToolPlaybook, ...]:
        """Return every registered playbook."""
        return self.playbook_engine.list()

    def get_playbook(self, playbook_id: str) -> ToolPlaybook | None:
        """Return a playbook by id or ``None``."""
        return self.playbook_engine.get(playbook_id)

    def playbooks_by_mission(self, mission_type: str) -> tuple[ToolPlaybook, ...]:
        """Return playbooks appropriate for ``mission_type``."""
        return self.playbook_engine.by_mission(mission_type)

    def playbooks_by_category(self, category: ToolPlaybookCategory) -> tuple[ToolPlaybook, ...]:
        """Return playbooks in ``category``."""
        return self.playbook_engine.by_category(category)

    # -- selection --------------------------------------------------------

    def select(
        self,
        capability: str,
        *,
        mission_type: str = "bug-bounty",
        target_type: str = "",
        limit: int = 5,
        authorization_granted: bool = False,
    ) -> list[ToolSelectionDecision]:
        """Return explainable tool selections for ``capability``."""
        return self.selector.select(
            capability,
            mission_type=mission_type,
            target_type=target_type,
            limit=limit,
            authorization_granted=authorization_granted,
        )

    def select_best(
        self,
        capability: str,
        *,
        mission_type: str = "bug-bounty",
        target_type: str = "",
        authorization_granted: bool = False,
    ) -> ToolSelectionDecision:
        """Return the single best explainable selection."""
        return self.selector.select_best(
            capability,
            mission_type=mission_type,
            target_type=target_type,
            authorization_granted=authorization_granted,
        )

    # -- history ----------------------------------------------------------

    def record_run(
        self,
        tool_id: str,
        target: str,
        *,
        tool_version: str = "",
        mission_id: str = "",
        configuration: dict[str, object] | None = None,
        status: ToolHistoryStatus = ToolHistoryStatus.COMPLETED,
        learned: str = "",
        unknown: str = "",
    ) -> ToolHistoryEntry:
        """Record a tool run against a target."""
        return self.history_engine.record_run(
            tool_id,
            target,
            tool_version=tool_version,
            mission_id=mission_id,
            configuration=configuration,
            status=status,
            learned=learned,
            unknown=unknown,
        )

    def history(self, target: str) -> tuple[ToolHistoryEntry, ...]:
        """Return recorded history for ``target``, newest first."""
        return self.history_engine.history(target)

    def has_executed(self, target: str, tool_id: str) -> bool:
        """Return ``True`` when ``tool_id`` already ran against ``target``."""
        return self.history_engine.has_executed(target, tool_id)

    # -- coverage ---------------------------------------------------------

    def coverage(self) -> ToolCoverageReport:
        """Return the current arsenal coverage report."""
        return self.coverage_engine.report()

    # -- datasets ---------------------------------------------------------

    def datasets(self) -> tuple[ToolDataset, ...]:
        """Return every registered dataset."""
        return self.dataset_registry.list()

    def get_dataset(self, dataset_id: str) -> ToolDataset | None:
        """Return a dataset by id or ``None``."""
        return self.dataset_registry.get(dataset_id)

    # -- version awareness ------------------------------------------------

    def check_version(self, tool_id: str, installed_version: str) -> object:
        """Return a version compatibility check result."""
        return self.versioning.check(tool_id, installed_version)

    def version_ok(self, tool_id: str, installed_version: str) -> bool:
        """Return ``True`` when the installed version satisfies constraints."""
        return self.versioning.installed_ok(tool_id, installed_version)

    # -- regression / replay (delegated) ----------------------------------

    @property
    def regression_engine(self) -> ParserRegressionEngine:
        """The parser regression engine."""
        return self.regression

    @property
    def replay_engine(self) -> ToolResultReplay:
        """The stored-result replay engine."""
        return self.replay

    # -- arsenal manifest --------------------------------------------------

    def arsenal(self) -> UniversalSecurityArsenal:
        """Return a :class:`UniversalSecurityArsenal` over the current state.

        The manifest aggregates every registered profile, capability, edge,
        playbook and dataset into the machine-readable universal security
        arsenal.
        """
        from hunterx.tools.mastery.arsenal import UniversalSecurityArsenal

        return UniversalSecurityArsenal(
            registry=self.registry,
            relationships=self.relationship_graph,
            playbooks=self.playbook_engine,
            datasets=self.dataset_registry,
        )

    def export_manifest(self, path: str) -> None:
        """Write the universal security arsenal manifest to ``path``."""
        self.arsenal().export(path)
