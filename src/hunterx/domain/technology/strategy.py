# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology fingerprinting collection strategy.

Maps an execution mode (passive/active/hybrid) and a target onto the concrete
set of fingerprinting tools and analyses the capability should run. The
strategy is a pure function of (mode, target, requested features) so the same
inputs always yield the same plan, and it fails closed for passive postures
(no new HTTP traffic is generated — only existing intelligence is consumed).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from hunterx.domain.recon.models import ReconMode
from hunterx.domain.technology.models import TechnologyCategory

#: Tools available for direct (active) fingerprinting.
_ACTIVE_TOOLS = ("httpx", "whatweb", "signature")

#: Passive postures run no fingerprinting tools (existing intelligence only).
_PASSIVE_TOOLS = ()


@dataclass(frozen=True, slots=True)
class TechStrategy:
    """A concrete fingerprinting collection plan.

    Attributes:
        target: the target value (hostname, domain, IP or URL).
        target_kind: canonical target kind.
        mode: the execution posture.
        tools: the tool ids to run.
        categories: canonical categories to collect (empty = all).
        include_versions: whether to attempt version detection.
        min_confidence: minimum confidence for a technology to be retained.
        with_history: whether to compare against historical observations.
        with_existing: whether to fold in existing TIDB intelligence.
        max_concurrency: execution concurrency ceiling.

    """

    target: str
    target_kind: str = "hostname"
    mode: ReconMode = ReconMode.HYBRID
    tools: tuple[str, ...] = _ACTIVE_TOOLS
    categories: tuple[TechnologyCategory, ...] = ()
    include_versions: bool = True
    min_confidence: float = 0.4
    with_history: bool = False
    with_existing: bool = True
    max_concurrency: int = 4


class TechStrategyBuilder:
    """Build a :class:`TechStrategy` for a target and mode."""

    def build(
        self,
        target: str,
        *,
        mode: ReconMode | str = ReconMode.HYBRID,
        target_kind: str = "",
        tools: tuple[str, ...] = (),
        categories: tuple[TechnologyCategory | str, ...] = (),
        include_versions: bool | None = None,
        min_confidence: float | None = None,
        with_history: bool = False,
        with_existing: bool | None = None,
        max_concurrency: int = 4,
    ) -> TechStrategy:
        """Build the strategy for ``target``."""
        if not target_kind:
            target_kind = _infer_target_kind(target)
        parsed_mode = _mode(mode)
        parsed_categories = tuple(_category(value) for value in categories)
        return TechStrategy(
            target=str(target).strip(),
            target_kind=target_kind,
            mode=parsed_mode,
            tools=tuple(tools) if tools else self.tools_for(parsed_mode),
            categories=parsed_categories,
            include_versions=_feature_default(parsed_mode, include_versions),
            min_confidence=min_confidence if min_confidence is not None else 0.4,
            with_history=with_history,
            with_existing=_feature_default(parsed_mode, with_existing),
            max_concurrency=max(1, max_concurrency),
        )

    def tools_for(self, mode: ReconMode) -> tuple[str, ...]:
        """Return the tool ids available for a posture (empty in passive)."""
        return () if mode is ReconMode.PASSIVE else _ACTIVE_TOOLS


def _feature_default(mode: ReconMode, requested: bool | None) -> bool:
    """Default a feature off for passive postures unless requested."""
    if requested is not None:
        return requested
    return mode is not ReconMode.PASSIVE


def _mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    try:
        return ReconMode(str(mode).lower())
    except ValueError:
        return ReconMode.HYBRID


def _infer_target_kind(value: str) -> str:
    """Infer a canonical target kind from a target value."""
    candidate = str(value).strip()
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if "/" in candidate:
        try:
            ipaddress.ip_network(candidate, strict=False)
            return "cidr"
        except ValueError:
            return "hostname"
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        return "domain" if candidate.count(".") == 1 else "hostname"


def _category(value: TechnologyCategory | str) -> TechnologyCategory:
    if isinstance(value, TechnologyCategory):
        return value
    try:
        return TechnologyCategory(str(value).lower())
    except ValueError:
        return TechnologyCategory.OTHER
