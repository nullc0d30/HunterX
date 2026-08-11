# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Rules generators: execution, mission and workflow rules.

Emits the execution rules (permissions, sandbox, retry policy), the mission
rules (which mission profiles a tool participates in) and the workflow rules
(stages, parallelism, approvals, fallbacks) of a Tool Integration Pack.
"""

from __future__ import annotations

from hunterx.domain.tool_factory import PackArtifactKind, render_yaml
from hunterx.tools.factory.generators.base import PackContext, PackGenerator


class ExecutionRulesGenerator(PackGenerator):
    """Generates the execution rules (``rules/execution.yaml``)."""

    name = "execution-rules"
    description = "Generates the execution rules record."

    def generate(self, ctx: PackContext):
        """Emit the execution rules record."""
        spec = ctx.spec
        data = {
            "tool_id": spec.pack_id,
            "permissions": list(spec.permissions),
            "sandbox": True,
            "timeout_seconds": 0,
            "retry_policy": {
                "max_attempts": 1,
                "base_delay_s": 1.0,
                "retryable_kinds": [],
            },
            "resource_limits": {
                "max_cpu_percent": 0,
                "max_memory_mb": 0,
                "max_disk_mb": 0,
                "network_allowed": "network" in spec.permissions,
            },
        }
        return [self.file("rules/execution.yaml", render_yaml(data) + "\n", PackArtifactKind.EXECUTION_RULES)]


class MissionRulesGenerator(PackGenerator):
    """Generates the mission rules (``rules/mission.yaml``)."""

    name = "mission-rules"
    description = "Generates the mission rules record."

    def generate(self, ctx: PackContext):
        """Emit the mission rules record."""
        spec = ctx.spec
        data = {
            "tool_id": spec.pack_id,
            "mission_profiles": list(spec.mission_profiles),
            "targets": list(spec.targets),
            "capabilities": list(spec.capabilities),
            "phases": [],
            "approval_required": False,
            "scheduling": {"priority": "medium", "max_concurrency": 0},
        }
        return [self.file("rules/mission.yaml", render_yaml(data) + "\n", PackArtifactKind.MISSION_RULES)]


class WorkflowRulesGenerator(PackGenerator):
    """Generates the workflow rules (``rules/workflow.yaml``)."""

    name = "workflow-rules"
    description = "Generates the workflow rules record."

    def generate(self, ctx: PackContext):
        """Emit the workflow rules record."""
        spec = ctx.spec
        data = {
            "tool_id": spec.pack_id,
            "stages": [
                {"id": "input", "description": "Validate and prepare inputs."},
                {"id": "execute", "description": "Run the tool binary."},
                {"id": "parse", "description": "Parse raw output."},
                {"id": "normalize", "description": "Normalize records into findings."},
                {"id": "store", "description": "Persist findings and evidence."},
            ],
            "parallelism": "sequential",
            "fallbacks": [],
            "approvals": [],
            "inputs_schema": "schemas/input.json",
            "outputs_schema": "schemas/output.json",
        }
        return [self.file("rules/workflow.yaml", render_yaml(data) + "\n", PackArtifactKind.WORKFLOW_RULES)]
