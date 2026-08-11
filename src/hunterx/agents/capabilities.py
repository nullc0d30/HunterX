# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Agent capability helpers."""

from __future__ import annotations

from collections.abc import Iterable

from hunterx.agents.base import AgentCapability


class CapabilitySet(frozenset):
    """A frozenset of :class:`AgentCapability` values with query helpers."""

    def __new__(cls, capabilities: Iterable[AgentCapability] = ()) -> CapabilitySet:
        """Construct a frozen set from an iterable of capabilities."""
        return super().__new__(cls, capabilities)  # type: ignore[arg-type]

    def requires(self, capability: AgentCapability) -> bool:
        """Return ``True`` when the set includes ``capability``."""
        return capability in self

    @classmethod
    def from_names(cls, names: Iterable[str]) -> CapabilitySet:
        """Build a set from capability names (case-insensitive)."""
        return cls(AgentCapability(name) for name in names)
