# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Readiness subsystem.

Discovers, validates, provisions and verifies the external security tools the
framework integrates BEFORE a mission attempts to use them:

    HunterX installation
        ↓
    Environment discovery
        ↓
    Tool inventory
        ↓
    Capability validation
        ↓
    Missing tool detection
        ↓
    Automatic provisioning/install where supported
        ↓
    Post-install verification
        ↓
    Tool registration
        ↓
    Capability availability
        ↓
    Mission preflight
        ↓
    Tool execution

The subsystem never hardcodes tool knowledge in the mission planner: tool
definitions are derived from the authoritative Tool Intelligence Platform (TIP)
registry and merged with a trusted static installation manifest
(:mod:`hunterx.tools.readiness.manifest`). It reuses the existing Tool
Integration SDK engine — there is no second tool registry.
"""

from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.discovery import ToolDiscovery
from hunterx.tools.readiness.models import (
    CapabilityLevel,
    CapabilityReadiness,
    InstallMethod,
    InstallOutcome,
    PreflightResult,
    PreflightStatus,
    ReadinessReport,
    ToolDefinition,
    ToolReadiness,
    ToolReadinessStatus,
)
from hunterx.tools.readiness.platform import PlatformDetector, PlatformInfo
from hunterx.tools.readiness.preflight import (
    MissionCapabilityResolver,
    MissionPreflight,
)
from hunterx.tools.readiness.provisioner import ToolProvisioner
from hunterx.tools.readiness.service import ToolReadinessService

__all__ = [
    "CapabilityLevel",
    "CapabilityReadiness",
    "InstallMethod",
    "InstallOutcome",
    "MissionCapabilityResolver",
    "MissionPreflight",
    "PlatformDetector",
    "PlatformInfo",
    "PreflightResult",
    "PreflightStatus",
    "ReadinessReport",
    "ToolDefinition",
    "ToolDefinitionBuilder",
    "ToolDiscovery",
    "ToolProvisioner",
    "ToolReadiness",
    "ToolReadinessService",
    "ToolReadinessStatus",
]
