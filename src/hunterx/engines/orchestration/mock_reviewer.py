# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""A simple mock reviewer for testing."""

from __future__ import annotations
from hunterx.engines.orchestration.executor import MissionRunResult

class SimpleMockReviewer:
    """A reviewer that accepts results if they contain evidence."""

    def review(self, result: MissionRunResult) -> bool:
        """Accepts result if there is at least one evidence record."""
        # Simple logic: count total evidence across all outcomes
        total_evidence = sum(outcome.evidence_count for outcome in result.outcomes.values())
        print(f"Mock Reviewer: Found {total_evidence} evidence records.")
        return total_evidence > 0
