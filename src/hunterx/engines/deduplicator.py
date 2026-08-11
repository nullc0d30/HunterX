# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deduplication engine.

Determines whether a finding is a duplicate of an already-stored finding by
comparing stable content hashes.
"""

from __future__ import annotations

from hunterx.domain.entities import Finding
from hunterx.domain.ports.repositories import FindingRepository
from hunterx.domain.services.deduplicator import DeduplicatorService


class ContentDeduplicator(DeduplicatorService):
    """Deduplicate findings by content hash via the repository port."""

    def __init__(self, repository: FindingRepository) -> None:
        self._repository = repository

    def is_duplicate(self, finding: Finding) -> bool:
        """Return ``True`` when the finding's content hash already exists."""
        content_hash = finding.content_hash or finding.compute_content_hash()
        return self._repository.exists_by_content_hash(content_hash)
