# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence collection strategy."""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.cloud.models import infer_asset_type
from hunterx.domain.recon.models import ReconMode

_CLOUD_TOOLS = ("cloud-analysis",)


@dataclass(frozen=True, slots=True)
class CloudStrategy:
    """The collection strategy for one cloud intelligence run.

    Attributes:
        target: canonical target value.
        target_kind: canonical target kind.
        mode: execution posture.
        tools: selected analysis tool ids.
        include_existing: fold previously persisted TIDB cloud intelligence.
        include_history: diff against a supplied historical snapshot.
        min_confidence: minimum confidence for a record to be retained.
        max_concurrency: execution concurrency ceiling.

    """

    target: str
    target_kind: str = "hostname"
    mode: ReconMode = ReconMode.HYBRID
    tools: tuple[str, ...] = _CLOUD_TOOLS
    include_existing: bool = True
    include_history: bool = False
    min_confidence: float = 0.0
    max_concurrency: int = 4


class CloudStrategyBuilder:
    """Build a :class:`CloudStrategy` from run parameters."""

    def build(
        self,
        target: str,
        *,
        mode: ReconMode | str = ReconMode.HYBRID,
        target_kind: str = "",
        tools: tuple[str, ...] | None = None,
        include_existing: bool | None = None,
        include_history: bool = False,
        min_confidence: float | None = None,
        max_concurrency: int = 4,
    ) -> CloudStrategy:
        """Construct a strategy deterministically from the supplied parameters."""
        recon_mode = _mode(mode)
        kind = target_kind or infer_asset_type(target)
        selected = tuple(tools) if tools is not None else _CLOUD_TOOLS
        confidence = 0.0 if min_confidence is None else min_confidence
        return CloudStrategy(
            target=str(target).strip(),
            target_kind=kind,
            mode=recon_mode,
            tools=selected,
            include_existing=True if include_existing is None else include_existing,
            include_history=include_history,
            min_confidence=max(0.0, min(1.0, confidence)),
            max_concurrency=max(1, max_concurrency),
        )

    def tools_for(self, mode: ReconMode) -> tuple[str, ...]:
        """Return the analysis tools for a posture (always the in-process analyzer)."""
        return _CLOUD_TOOLS


def _mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    try:
        return ReconMode(str(mode).lower())
    except ValueError:
        return ReconMode.HYBRID
