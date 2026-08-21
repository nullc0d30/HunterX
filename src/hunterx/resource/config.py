# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — typed configuration.

The resource envelope of a mission is derived from the *effective* runtime
environment (physical host, VM, WSL, container/cgroup) and bounded by an
absolute safety ceiling. The absolute HunterX RAM ceiling is 3 GB by default;
the effective mission budget is always derived from the environment and never
assumes ``physical RAM == RAM available to HunterX``.

The configuration schema (:class:`ResourceSettings`) lives in the existing
HunterX configuration system (``hunterx.config.settings``) so every value is
exposed through ``HUNTERX_RESOURCE_*`` env vars and the ``resource:`` YAML
section. :class:`ResourceConfig` is the resolved, immutable view the governor
consumes.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.config.settings import ResourceSettings  # noqa: F401  # re-exported


@dataclass(frozen=True, slots=True)
class ResourceConfig:
    """Immutable resolved resource-governance configuration.

    Built from :class:`ResourceSettings` (the configuration schema) so the
    governor never depends on the pydantic layer. Tests may construct a
    :class:`ResourceConfig` directly.
    """

    memory_ceiling_mb: float = 3072.0
    host_headroom_ratio: float = 0.55
    budget_ratio: float = 0.5
    memory_soft_ratio: float = 0.6
    memory_high_ratio: float = 0.8
    memory_hard_ratio: float = 0.92
    system_emergency_ratio: float = 0.95
    cpu_budget_percent: float = 0.0
    max_tool_concurrency: int = 2
    max_probe_concurrency: int = 4
    max_model_concurrency: int = 1
    max_queue_depth: int = 500
    tool_timeout_s: float = 600.0
    model_timeout_s: float = 120.0
    mission_deadline_s: float = 0.0
    max_observations_in_memory: int = 1500
    max_hypotheses_in_memory: int = 600
    max_decisions_in_memory: int = 1500
    max_evidence_in_memory: int = 2000
    max_tool_executions_in_memory: int = 1500
    max_trace_in_memory: int = 1200
    max_negative_evidence_in_memory: int = 800
    max_attack_paths_in_memory: int = 1500
    max_model_context_observations: int = 60
    max_model_context_findings: int = 20
    max_model_context_paths: int = 30
    max_model_context_disproven: int = 200
    max_replan_cycles: int = 12
    max_probes_per_cycle: int = 12
    telemetry_interval_s: float = 5.0

    @classmethod
    def from_settings(cls, settings: ResourceSettings | None) -> ResourceConfig:
        """Build the resolved config from pydantic settings (defaults when ``None``)."""
        source = settings if settings is not None else ResourceSettings()
        return cls(
            memory_ceiling_mb=source.memory_ceiling_mb,
            host_headroom_ratio=source.host_headroom_ratio,
            budget_ratio=source.budget_ratio,
            memory_soft_ratio=source.memory_soft_ratio,
            memory_high_ratio=source.memory_high_ratio,
            memory_hard_ratio=source.memory_hard_ratio,
            system_emergency_ratio=source.system_emergency_ratio,
            cpu_budget_percent=source.cpu_budget_percent,
            max_tool_concurrency=source.max_tool_concurrency,
            max_probe_concurrency=source.max_probe_concurrency,
            max_model_concurrency=source.max_model_concurrency,
            max_queue_depth=source.max_queue_depth,
            tool_timeout_s=source.tool_timeout_s,
            model_timeout_s=source.model_timeout_s,
            mission_deadline_s=source.mission_deadline_s,
            max_observations_in_memory=source.max_observations_in_memory,
            max_hypotheses_in_memory=source.max_hypotheses_in_memory,
            max_decisions_in_memory=source.max_decisions_in_memory,
            max_evidence_in_memory=source.max_evidence_in_memory,
            max_tool_executions_in_memory=source.max_tool_executions_in_memory,
            max_trace_in_memory=source.max_trace_in_memory,
            max_negative_evidence_in_memory=source.max_negative_evidence_in_memory,
            max_attack_paths_in_memory=source.max_attack_paths_in_memory,
            max_model_context_observations=source.max_model_context_observations,
            max_model_context_findings=source.max_model_context_findings,
            max_model_context_paths=source.max_model_context_paths,
            max_model_context_disproven=source.max_model_context_disproven,
            max_replan_cycles=source.max_replan_cycles,
            max_probes_per_cycle=source.max_probes_per_cycle,
            telemetry_interval_s=source.telemetry_interval_s,
        )


@dataclass(frozen=True, slots=True)
class ResourceMetrics:
    """Human/operator telemetry snapshot of the resource governor."""

    state: str = "normal"
    rss_mb: float = 0.0
    peak_rss_mb: float = 0.0
    budget_mb: float = 0.0
    ceiling_mb: float = 0.0
    memory_pressure: float = 0.0
    system_memory_pressure: float = 0.0
    cpu_percent: float = 0.0
    cpu_cores: int = 0
    effective_memory_limit_mb: float = 0.0
    environment: str = ""
    active_tools: int = 0
    active_model_calls: int = 0
    process_count: int = 0
    mission_count: int = 0

    def to_dict(self) -> dict[str, float | int | str]:
        """Serialize to a JSON-safe mapping."""
        return {
            "state": self.state,
            "rss_mb": self.rss_mb,
            "peak_rss_mb": self.peak_rss_mb,
            "budget_mb": self.budget_mb,
            "ceiling_mb": self.ceiling_mb,
            "memory_pressure": self.memory_pressure,
            "system_memory_pressure": self.system_memory_pressure,
            "cpu_percent": self.cpu_percent,
            "cpu_cores": self.cpu_cores,
            "effective_memory_limit_mb": self.effective_memory_limit_mb,
            "environment": self.environment,
            "active_tools": self.active_tools,
            "active_model_calls": self.active_model_calls,
            "process_count": self.process_count,
            "mission_count": self.mission_count,
        }


__all__ = ["ResourceConfig", "ResourceMetrics", "ResourceSettings"]
