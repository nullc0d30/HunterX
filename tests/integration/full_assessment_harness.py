# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared harness for the v7.0.1 full-security-assessment orchestration tests.

Drives the real adaptive mission runner (planning → decision → execution →
ingestion → replan → probe → verify) over a deterministic fake execution engine
so the full lifecycle is exercised without external binaries or network access.
"""

from __future__ import annotations

from typing import Any

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory

#: Capability → registered tool candidates (mirrors the composition root).
DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("assetfinder",),
    "subdomain_enumeration": ("subfinder", "amass", "assetfinder"),
    "dns_enumeration": ("dnsx", "dig"),
    "port_discovery": ("nmap", "rustscan", "masscan"),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb", "wappalyzer"),
    "certificate_enumeration": ("certspotter", "crt.sh"),
    "endpoint_enumeration": ("httpx", "katana", "gospider"),
    "content_discovery": ("katana", "gospider"),
    "javascript_analysis": ("jsluice", "linkfinder"),
    "parameter_discovery": ("arjun", "x8"),
    "api_mapping": ("kiterunner", "nuclei"),
    "vulnerability_scanning": ("nuclei", "nikto"),
    "sql_injection": ("sqlmap", "ghauri"),
    "xss": ("dalfox", "xssstrike"),
    "ssrf": ("ffuf", "nuclei"),
    "ssti": ("sstimap", "tplmap"),
    "lfi": ("ffuf", "nuclei"),
    "idor": ("ffuf", "nuclei"),
    "api_security": ("nuclei", "kiterunner"),
    "graphql_security": ("inql", "graphqlmap"),
    "authentication_analysis": ("httpx", "nuclei"),
    "authorization_analysis": ("httpx", "nuclei"),
    "secret_detection": ("trufflehog", "gitleaks"),
    "dependency_check": ("osv-scanner", "trivy"),
}

#: Deterministic tool outputs for a rich web target with a real attack surface.
RICH_WEB_OUTPUTS: dict[str, dict[str, Any]] = {
    "assetfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}]},
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}]},
    "dnsx": {"records": ["api.localhost -> 127.0.0.1"]},
    "nmap": {"observations": [{"type": "port", "port": 3010, "state": "open"}]},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"]},
    "certspotter": {"certificates": ["localhost"]},
    "httpx": {"endpoints": ["/rest/products/search", "/api/products"]},
    "katana": {"endpoints": ["/rest/products/search?q=1", "/rest/user/whoami"]},
    "jsluice": {"javascript": {"analyses": [{"endpoints": [{"url": "/rest/products/search"}]}]}},
    "arjun": {"parameters": ["q", "id"]},
    "kiterunner": {"endpoints": ["/api/products", "/rest/products/search"]},
    "nuclei": {"findings": [{"template": "deprecated-tls", "severity": "medium", "info": "TLS 1.1"}]},
    "sqlmap": {"findings": [{"vulnerability_class": "sql-injection", "severity": "high"}]},
    "dalfox": {"findings": [{"vulnerability_class": "xss", "severity": "high"}]},
    "ffuf": {"parameters": ["q", "id"]},
}

#: Deterministic tool outputs for a minimal web target (recon only findings).
MINIMAL_WEB_OUTPUTS: dict[str, dict[str, Any]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}]},
    "dnsx": {"records": ["api.localhost -> 127.0.0.1"]},
    "nmap": {"observations": [{"type": "port", "port": 443, "state": "open"}]},
    "whatweb": {"name": "nginx"},
    "certspotter": {"certificates": ["localhost"]},
    "httpx": {},
}


class FakeExecutionEngine:
    """Deterministic :class:`ExecutionEngine` double for mission tests."""

    def __init__(
        self,
        outputs: dict[str, dict[str, Any]] | None = None,
        *,
        fail_tools: tuple[str, ...] = (),
        error: str = "tool execution failed (fake)",
        not_found_output: dict[str, Any] | None = None,
    ) -> None:
        self._outputs = dict(outputs or {})
        self._fail_tools = set(fail_tools)
        self._error = error
        self._not_found = not_found_output or {"value": "no content"}
        self.calls: list[Any] = []

    def execute(self, context: Any) -> Any:
        from hunterx.domain.execution import (
            ExecutionOutput,
            ExecutionResult,
            ExecutionStatus,
            FailureKind,
            OutputFormat,
        )
        from hunterx.tools.sdk.pipeline import PipelineResult
        from hunterx.tools.sdk.session import ExecutionSession

        self.calls.append(context)
        tool_id = context.tool_id
        if tool_id in self._fail_tools:
            result = ExecutionResult(
                execution_id=context.execution_id,
                tool_id=tool_id,
                status=ExecutionStatus.FAILED,
                error=self._error,
                failure_kind=FailureKind.NOT_RETRYABLE,
                output=ExecutionOutput(exit_code=1, stderr=self._error, formats={OutputFormat.STDERR}),
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                duration_ms=10,
            )
        else:
            content = self._outputs.get(tool_id, self._not_found)
            result = ExecutionResult(
                execution_id=context.execution_id,
                tool_id=tool_id,
                status=ExecutionStatus.COMPLETED,
                output=ExecutionOutput(exit_code=0, json=content, formats={OutputFormat.JSON}),
                started_at="2026-01-01T00:00:00Z",
                completed_at="2026-01-01T00:00:01Z",
                duration_ms=10,
            )
        return PipelineResult(result=result, session=ExecutionSession(context), attempts=1)


def build_runner(fake: FakeExecutionEngine) -> tuple[MissionExecutionService, MissionOrchestrationService, AdaptiveMissionPlanningEngine]:
    """Assemble the real adaptive runner over a fake execution engine."""
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=dict(DEFAULT_CANDIDATES),
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
    )
    return runner, orchestration, planning


__all__ = [
    "DEFAULT_CANDIDATES",
    "FakeExecutionEngine",
    "MINIMAL_WEB_OUTPUTS",
    "RICH_WEB_OUTPUTS",
    "build_runner",
]
