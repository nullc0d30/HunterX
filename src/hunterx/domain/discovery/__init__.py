# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery — domain layer.

Target-agnostic vocabulary and data contracts for the Phase 4 universal
discovery pipeline: the ordered discovery stages, honest provider states,
provenance-rich discovered assets and the declarative stage plan. The
application layer (:mod:`hunterx.application.discovery`) drives the execution
engine against this plan.
"""

from hunterx.domain.discovery.canonical import (
    DiscoveryDeduper,
    asset_key,
    canonical_host,
    canonical_host_port,
    canonical_ip,
    canonical_port,
    canonical_url,
    host_from_url,
    is_hostname,
    is_ip,
)
from hunterx.domain.discovery.enums import DiscoveryLayer, DiscoveryStage, DiscoveryState
from hunterx.domain.discovery.models import (
    DiscoveredAsset,
    DiscoveryEvidence,
    DiscoveryProviderResult,
    DiscoveryRun,
    DiscoveryStageResult,
)
from hunterx.domain.discovery.pipeline import ProviderSpec, StageDefinition, StagePlan

__all__ = [
    "DiscoveredAsset",
    "DiscoveryDeduper",
    "DiscoveryEvidence",
    "DiscoveryLayer",
    "DiscoveryProviderResult",
    "DiscoveryRun",
    "DiscoveryStage",
    "DiscoveryStageResult",
    "DiscoveryState",
    "ProviderSpec",
    "StageDefinition",
    "StagePlan",
    "asset_key",
    "canonical_host",
    "canonical_host_port",
    "canonical_ip",
    "canonical_port",
    "canonical_url",
    "host_from_url",
    "is_hostname",
    "is_ip",
]
