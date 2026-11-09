# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base interface for mission result reviewers."""

from __future__ import annotations
from typing import Protocol, runtime_checkable
from hunterx.engines.orchestration.executor import MissionRunResult

@runtime_checkable
class BaseReviewer(Protocol):
    """Interface for agents that review mission outcomes."""

    def review(self, result: MissionRunResult) -> bool:
        """Review the mission result and return True if accepted."""
        ...
