# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reconnaissance capability domain.

Pure domain contracts for the recon capability: discovery records, targets,
modes, confidence scoring and cross-tool correlation. No I/O, no execution.
"""

from __future__ import annotations

from hunterx.domain.recon.confidence import ConfidenceEngine, ConfidencePolicy
from hunterx.domain.recon.correlator import ReconCorrelator
from hunterx.domain.recon.models import (
    DiscoveryKind,
    DiscoveryRecord,
    ReconBatch,
    ReconExecutionSummary,
    ReconMode,
    ReconTarget,
    infer_ip_version,
)

__all__ = [
    "ConfidenceEngine",
    "ConfidencePolicy",
    "DiscoveryKind",
    "DiscoveryRecord",
    "ReconBatch",
    "ReconCorrelator",
    "ReconExecutionSummary",
    "ReconMode",
    "ReconTarget",
    "infer_ip_version",
]
