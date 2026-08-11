# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Correlation domain service.

The correlator groups related findings into attack-path style clusters so the
final report tells a story instead of listing disconnected observations.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from hunterx.domain.entities import Finding


@dataclass(frozen=True, slots=True)
class CorrelationGroup:
    """A cluster of related findings.

    Attributes:
        group_id: stable group identifier.
        finding_ids: identifiers of the findings in the group.
        narrative: human-readable description of the relationship.

    """

    group_id: str
    finding_ids: tuple[str, ...] = ()
    narrative: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


class CorrelatorService(abc.ABC):
    """Contract for finding correlation."""

    @abc.abstractmethod
    def correlate(self, findings: list[Finding]) -> list[CorrelationGroup]:
        """Group related findings into correlation clusters."""
