# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deduplication domain service."""

from __future__ import annotations

import abc

from hunterx.domain.entities import Finding


class DeduplicatorService(abc.ABC):
    """Contract for deduplicating findings by content."""

    @abc.abstractmethod
    def is_duplicate(self, finding: Finding) -> bool:
        """Return ``True`` when ``finding`` duplicates an already-known finding."""
