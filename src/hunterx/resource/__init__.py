# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-aware execution and resource governor.

The single authoritative resource-governance layer for HunterX missions.
"""

from __future__ import annotations

from hunterx.resource.admission import Admission
from hunterx.resource.bounds import (
    apply_mission_bounds,
    content_bytes,
    keep_recent,
    trim_generic,
    trim_hypotheses,
    truncate_content,
)
from hunterx.resource.config import ResourceConfig, ResourceMetrics, ResourceSettings
from hunterx.resource.detect import (
    EnvironmentInfo,
    EnvironmentKind,
    describe_environment,
    detect_cgroup_memory,
    detect_cpu_quota,
    detect_effective_cpu_count,
    detect_environment,
)
from hunterx.resource.governor import ResourceGovernor
from hunterx.resource.sampler import ProcessSnapshot, ProcessTreeSampler
from hunterx.resource.state import ResourceState, state_severity
from hunterx.resource.telemetry import MissionMemoryProbe, TelemetryLog

__all__ = [
    "Admission",
    "EnvironmentInfo",
    "EnvironmentKind",
    "MissionMemoryProbe",
    "ProcessSnapshot",
    "ProcessTreeSampler",
    "ResourceConfig",
    "ResourceGovernor",
    "ResourceMetrics",
    "ResourceSettings",
    "ResourceState",
    "TelemetryLog",
    "apply_mission_bounds",
    "content_bytes",
    "describe_environment",
    "detect_cgroup_memory",
    "detect_cpu_quota",
    "detect_effective_cpu_count",
    "detect_environment",
    "keep_recent",
    "state_severity",
    "trim_generic",
    "trim_hypotheses",
    "truncate_content",
]
