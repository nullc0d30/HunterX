# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Risk scoring domain service."""

from __future__ import annotations

import abc

from hunterx.domain.entities import Finding
from hunterx.domain.value_objects import RiskScore


class RiskScorerService(abc.ABC):
    """Contract for computing a normalized risk score for a finding."""

    @abc.abstractmethod
    def score(self, finding: Finding) -> RiskScore:
        """Compute the normalized risk score for a finding."""
