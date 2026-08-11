# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Mastery port.

Defines the Sprint 025 contract between the mastery layer and the rest of
HunterX: master profiles, relationship queries, playbooks, mission-aware
selection, target history, coverage, datasets, version awareness, parser
regression and result replay. Every subsystem consults this port instead of
reaching into concrete mastery implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

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


class ToolMasteryPort(ABC):
    """The contract every mastery consumer depends on."""

    # -- registry ---------------------------------------------------------

    @abstractmethod
    def register_profile(self, profile: ToolMasterProfile) -> None: ...

    @abstractmethod
    def get_profile(self, tool_id: str) -> ToolMasterProfile | None: ...

    @abstractmethod
    def profiles(self) -> tuple[ToolMasterProfile, ...]: ...

    @abstractmethod
    def tool_ids(self) -> tuple[str, ...]: ...

    @abstractmethod
    def providers_of(self, capability_id: str) -> tuple[str, ...]: ...

    @abstractmethod
    def by_support_level(self, level: ToolSupportLevel) -> tuple[str, ...]: ...

    # -- relationships ----------------------------------------------------

    @abstractmethod
    def relationships(self, tool_id: str) -> list[ToolRelationship]: ...

    @abstractmethod
    def next_tools(self, tool_id: str) -> list[str]: ...

    @abstractmethod
    def previous_tools(self, tool_id: str) -> list[str]: ...

    @abstractmethod
    def alternatives(self, tool_id: str) -> list[str]: ...

    @abstractmethod
    def unknown_tool_refs(self) -> list[str]: ...

    # -- playbooks --------------------------------------------------------

    @abstractmethod
    def playbooks(self) -> tuple[ToolPlaybook, ...]: ...

    @abstractmethod
    def get_playbook(self, playbook_id: str) -> ToolPlaybook | None: ...

    @abstractmethod
    def playbooks_by_mission(self, mission_type: str) -> tuple[ToolPlaybook, ...]: ...

    @abstractmethod
    def playbooks_by_category(self, category: ToolPlaybookCategory) -> tuple[ToolPlaybook, ...]: ...

    # -- selection --------------------------------------------------------

    @abstractmethod
    def select(
        self,
        capability: str,
        *,
        mission_type: str = "bug-bounty",
        target_type: str = "",
        limit: int = 5,
        authorization_granted: bool = False,
    ) -> list[ToolSelectionDecision]: ...

    @abstractmethod
    def select_best(
        self,
        capability: str,
        *,
        mission_type: str = "bug-bounty",
        target_type: str = "",
        authorization_granted: bool = False,
    ) -> ToolSelectionDecision: ...

    # -- history ----------------------------------------------------------

    @abstractmethod
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
    ) -> ToolHistoryEntry: ...

    @abstractmethod
    def history(self, target: str) -> tuple[ToolHistoryEntry, ...]: ...

    @abstractmethod
    def has_executed(self, target: str, tool_id: str) -> bool: ...

    # -- coverage ---------------------------------------------------------

    @abstractmethod
    def coverage(self) -> ToolCoverageReport: ...

    # -- datasets ---------------------------------------------------------

    @abstractmethod
    def datasets(self) -> tuple[ToolDataset, ...]: ...

    @abstractmethod
    def get_dataset(self, dataset_id: str) -> ToolDataset | None: ...

    # -- version awareness ------------------------------------------------

    @abstractmethod
    def check_version(self, tool_id: str, installed_version: str) -> object: ...

    @abstractmethod
    def version_ok(self, tool_id: str, installed_version: str) -> bool: ...
