# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Compatibility engine.

Determines whether a tool can run in a given execution environment: operating
system, architecture, Python version, Docker/containerized execution, native
execution, cloud execution, and air-gapped operation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


@dataclass(frozen=True, slots=True)
class CompatibilityResult:
    """The outcome of a compatibility check.

    Attributes:
        compatible: whether the tool can run in the environment.
        reasons: human-readable findings.
        missing: requirements the environment does not satisfy.

    """

    compatible: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
    missing: tuple[str, ...] = field(default_factory=tuple)


class CompatibilityEngine:
    """Evaluate tool compatibility against execution environments.

    The engine combines the tool's declared :class:`ToolCompatibility` profile
    with metadata (platforms, architectures, execution type) and a target
    environment description.
    """

    def __init__(self, registry: ToolIntelligenceRegistry) -> None:
        self._registry = registry

    def check(
        self,
        tool_id: str,
        *,
        os_name: str = "",
        architecture: str = "",
        docker: bool = False,
        air_gapped: bool = False,
        cloud: bool = False,
    ) -> CompatibilityResult:
        """Check ``tool_id`` against an environment and return a verdict.

        When ``os_name``/``architecture`` are empty, the corresponding checks
        are skipped (treated as compatible).
        """
        profile = self._registry.get_compatibility(tool_id)
        reasons: list[str] = []
        missing: list[str] = []

        if profile is None:
            reasons.append("no compatibility profile declared")
            return CompatibilityResult(compatible=True, reasons=tuple(reasons))

        if os_name and profile.os and os_name not in profile.os:
            missing.append(f"os {os_name!r}")
            reasons.append(f"unsupported os: {os_name!r}")
        else:
            reasons.append("os compatible")

        if architecture and profile.architectures and architecture not in profile.architectures:
            missing.append(f"architecture {architecture!r}")
            reasons.append(f"unsupported architecture: {architecture!r}")
        else:
            reasons.append("architecture compatible")

        if docker and not profile.docker:
            missing.append("docker")
            reasons.append("not docker-compatible")
        else:
            reasons.append("docker compatible")

        if cloud and not profile.cloud:
            missing.append("cloud")
            reasons.append("not cloud-compatible")
        else:
            reasons.append("cloud compatible")

        if air_gapped and not profile.air_gapped:
            missing.append("air-gapped")
            reasons.append("requires network access")
        else:
            reasons.append("air-gapped compatible")

        compatible = not missing
        return CompatibilityResult(
            compatible=compatible,
            reasons=tuple(reasons),
            missing=tuple(missing),
        )

    def available_backends(self, tool_id: str) -> list[str]:
        """Return the execution backends a tool supports as backend names."""
        profile = self._registry.get_compatibility(tool_id)
        if profile is None:
            return ["native"]
        backends: list[str] = []
        if profile.native:
            backends.append("native")
        if profile.docker:
            backends.append("docker")
        if profile.containerized:
            backends.append("containerized")
        if profile.cloud:
            backends.append("cloud")
        if profile.air_gapped:
            backends.append("air-gapped")
        return backends
