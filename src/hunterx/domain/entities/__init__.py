# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Domain entities.

Entities are domain objects with an identity and a lifecycle. They are plain
dataclasses with validation in ``__post_init__`` and helper methods for state
transitions. Persistence details are deliberately absent — repositories
(``hunterx.domain.ports``) map entities to storage.
"""

from __future__ import annotations

from hunterx.domain.entities.asset import Asset
from hunterx.domain.entities.evidence import Evidence, EvidenceKind
from hunterx.domain.entities.finding import Finding
from hunterx.domain.entities.mission import (
    Mission,
    MissionKind,
    MissionPriority,
    MissionStatus,
)
from hunterx.domain.entities.report import Report, ReportKind, ReportStatus
from hunterx.domain.entities.scan import Scan, ScanStatus
from hunterx.domain.entities.target import Target, TargetKind

__all__ = [
    "Asset",
    "Evidence",
    "EvidenceKind",
    "Finding",
    "Mission",
    "MissionPriority",
    "MissionStatus",
    "MissionKind",
    "Target",
    "TargetKind",
    "Report",
    "ReportKind",
    "ReportStatus",
    "Scan",
    "ScanStatus",
]
