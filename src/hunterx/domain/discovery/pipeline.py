# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery pipeline plan (pure data structures).

A :class:`StagePlan` describes which tools run at which :class:`DiscoveryStage`
and how each tool's payload is turned into canonical assets and attack-surface
observations. The plan is declarative and target-agnostic: the tool ids are
injected from the tool registries by the application layer (this module never
hardcodes a provider list), and the converters are referenced by name so the
plan stays importable without the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.discovery.enums import DiscoveryStage


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """One provider in the stage plan.

    Attributes:
        tool_id: tool id as registered with the execution engine.
        kind: payload family the converter understands (``recon``, ``dns``,
            ``livehost``, ``tech``, ``web``, ``content``, ``parameter``,
            ``javascript``, ``api``, ``auth``).
        payload_key: JSON key under which the provider writes its canonical
            payload (``discoveries``, ``dns_records``, ``observations``,
            ``technologies``, ``crawl``, ``content``, ``parameters``,
            ``javascript``, ``apis``, ``auth``).
        posture: required execution posture (``passive``/``active``/``hybrid``);
            providers whose minimum posture exceeds the run mode are reported
            UNAVAILABLE rather than run.
        requires: asset kinds the provider consumes (e.g. a host provider needs
            discovered hostnames); the pipeline passes these as parameters.

    """

    tool_id: str
    kind: str
    payload_key: str = ""
    posture: str = "hybrid"
    requires: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StageDefinition:
    """Definition of one discovery stage.

    Attributes:
        stage: the :class:`DiscoveryStage`.
        providers: provider specs that contribute to this stage.
        optional: True when the stage may be skipped with NOT_APPLICABLE when no
            evidence of the capability exists (e.g. GraphQL).
        title: human-readable title for reports.

    """

    stage: DiscoveryStage
    providers: tuple[ProviderSpec, ...] = ()
    optional: bool = False
    title: str = ""


@dataclass(frozen=True, slots=True)
class StagePlan:
    """Ordered, declarative discovery pipeline.

    Attributes:
        stages: ordered stage definitions (the execution order).
        by_tool: ``{tool_id: (stage, ProviderSpec)}`` lookup for fast dispatch.

    """

    stages: tuple[StageDefinition, ...] = ()
    by_tool: dict[str, tuple[DiscoveryStage, ProviderSpec]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        by_tool: dict[str, tuple[DiscoveryStage, ProviderSpec]] = {}
        for definition in self.stages:
            for provider in definition.providers:
                by_tool[provider.tool_id] = (definition.stage, provider)
        object.__setattr__(self, "by_tool", by_tool)

    def stage(self, stage: DiscoveryStage) -> StageDefinition | None:
        """Return the definition for a stage (``None`` when absent)."""
        for definition in self.stages:
            if definition.stage is stage:
                return definition
        return None

    def tools_for(self, stage: DiscoveryStage) -> list[str]:
        """Return the tool ids registered for a stage."""
        definition = self.stage(stage)
        return [provider.tool_id for provider in definition.providers] if definition else []

    def tool_ids(self) -> list[str]:
        """Return every tool id in the plan."""
        return [provider.tool_id for definition in self.stages for provider in definition.providers]

    def provider_for(self, tool_id: str) -> tuple[DiscoveryStage, ProviderSpec] | None:
        """Return the (stage, spec) for a tool id (``None`` when unknown)."""
        return self.by_tool.get(tool_id)


__all__ = ["ProviderSpec", "StageDefinition", "StagePlan"]