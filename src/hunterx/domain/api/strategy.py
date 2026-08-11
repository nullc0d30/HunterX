# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence collection strategy.

Maps an execution mode (passive/active/hybrid) and a target onto the concrete
set of API intelligence tools the capability should run. The strategy is a pure
function of (mode, target, requested features) so the same inputs always yield
the same plan, and it fails closed for passive postures: no new traffic is
generated — only existing intelligence is consumed.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.api.models import ApiTarget
from hunterx.domain.recon.models import ReconMode

#: Tools that fetch/scan in active postures (require network traffic).
_ACTIVE_TOOLS = (
    "api-openapi",
    "api-swagger",
    "api-soap",
)

#: Tools that derive intelligence from existing observations (no traffic).
_PASSIVE_TOOLS = (
    "api-hints",
    "api-graphql",
    "api-websocket",
)


@dataclass(frozen=True, slots=True)
class ApiStrategy:
    """A concrete API intelligence collection plan.

    Attributes:
        target: the target value (hostname, domain, IP or URL).
        target_kind: canonical target kind.
        mode: the execution posture.
        tools: the tool ids to run.
        include_specs: whether to locate spec documents.
        include_undocumented: whether to model undocumented endpoints.
        include_auth: whether to model auth/authorization.
        include_indicators: whether to model rate-limit/pagination/filter.
        min_confidence: minimum confidence for a record to be retained.
        with_history: whether to compare against historical observations.
        with_existing: whether to fold in existing TIDB intelligence.
        max_operations: ceiling on operations modelled per run.
        max_spec_size_bytes: ceiling on spec document size.

    """

    target: str
    target_kind: str = "hostname"
    mode: ReconMode = ReconMode.HYBRID
    tools: tuple[str, ...] = ()
    include_specs: bool = True
    include_undocumented: bool = True
    include_auth: bool = True
    include_indicators: bool = True
    min_confidence: float = 0.25
    with_history: bool = True
    with_existing: bool = True
    max_operations: int = 2000
    max_spec_size_bytes: int = 5 * 1024 * 1024

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", _parse_mode(self.mode))
        object.__setattr__(self, "tools", tuple(self.tools))

    def should_locate_specs(self) -> bool:
        """Return whether spec documents are part of the plan."""
        return self.include_specs and bool(set(self.tools) & {"api-openapi", "api-swagger", "api-soap", "api-hints"})


class ApiStrategyBuilder:
    """Build an :class:`ApiStrategy` from a mode, target and feature flags.

    The builder is a pure function of its inputs: the same call always yields
    the same strategy.
    """

    def build(
        self,
        target: ApiTarget | str,
        *,
        mode: ReconMode | str = ReconMode.HYBRID,
        include_specs: bool = True,
        include_undocumented: bool = True,
        include_auth: bool = True,
        include_indicators: bool = True,
        min_confidence: float = 0.25,
        with_history: bool = True,
        with_existing: bool = True,
        max_operations: int = 2000,
        max_spec_size_bytes: int = 5 * 1024 * 1024,
    ) -> ApiStrategy:
        """Build the strategy for ``target`` and ``mode``."""
        if isinstance(target, ApiTarget):
            value, target_kind = target.value, target.target_type
        else:
            value, target_kind = str(target), "hostname"
        parsed_mode = _parse_mode(mode)

        if parsed_mode is ReconMode.PASSIVE:
            tools = _PASSIVE_TOOLS
        elif parsed_mode is ReconMode.ACTIVE:
            tools = _ACTIVE_TOOLS
        else:
            tools = _ACTIVE_TOOLS + _PASSIVE_TOOLS

        return ApiStrategy(
            target=value.strip(),
            target_kind=target_kind,
            mode=parsed_mode,
            tools=tools,
            include_specs=include_specs,
            include_undocumented=include_undocumented,
            include_auth=include_auth,
            include_indicators=include_indicators,
            min_confidence=min_confidence,
            with_history=with_history,
            with_existing=with_existing,
            max_operations=max_operations,
            max_spec_size_bytes=max_spec_size_bytes,
        )


def _parse_mode(mode: ReconMode | str) -> ReconMode:
    if isinstance(mode, ReconMode):
        return mode
    try:
        return ReconMode(str(mode).lower())
    except ValueError:
        return ReconMode.HYBRID
