#!/usr/bin/env python3
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D103, E501  # diagnostic demo: single-purpose script
"""Behavioral demo: a rate-limited OpenRouter model must NOT exhaust the budget.

Reproduces the real regression: a wired model attacker that keeps hitting
HTTP 429 must terminate as an explicit blocked/AI-unavailable terminal — never
``resource_budget_exhausted`` while 984 executions remain.
"""
import http.server
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
for path in (SRC, ROOT):
    if path in sys.path:
        sys.path.remove(path)
sys.path.insert(0, ROOT)
sys.path.insert(0, SRC)

import dataclasses  # noqa: E402

from hunterx.application.ai_suggestion import AIActionSuggester  # noqa: E402
from hunterx.application.mission_execution import MissionExecutionService  # noqa: E402
from hunterx.application.mission_orchestration import MissionOrchestrationService  # noqa: E402
from hunterx.application.model_attacker import ModelAttacker  # noqa: E402
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine  # noqa: E402
from hunterx.domain.mission_orchestration.enums import StopCondition  # noqa: E402
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator  # noqa: E402
from hunterx.domain.model_attacker.reasoner import ModelReasoner  # noqa: E402
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine  # noqa: E402
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine  # noqa: E402
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory  # noqa: E402
from tests.framework.fakes import FakeExecutionEngine  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"hello": "world", "q": 1, "id": 2}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: D102
        pass


class _RateLimitedAI:
    def complete(self, prompt, *, model=None, temperature=0.0):  # noqa: ARG002
        error = RuntimeError("openrouter: rate limited (HTTP 429) - retry later")
        error.retry_after = 15.0  # type: ignore[attr-defined]
        raise error

    def embed(self, text):  # noqa: ARG002
        return []


_TARGET = "http://127.0.0.1:18080"
_CANDIDATES = {
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
    "endpoint_enumeration": ("httpx",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
}
_OUTPUTS = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}]},
    "dnsx": {"records": ["api.localhost -> 127.0.0.1"]},
    "nmap": {"ports": [18080]},
    "whatweb": {"name": "httpd", "technologies": ["python-http.server"]},
    "httpx": {"endpoints": ["/", "/api"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {"findings": []},
}


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES)
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    attacker = ModelAttacker(ModelReasoner(_RateLimitedAI()), max_cycles=8)
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs=dict(_OUTPUTS)),
        model_attacker=attacker,
        ai_suggester=AIActionSuggester(_RateLimitedAI(), provider="openrouter", model="nvidia/nemotron:free", min_interval_s=0.0),
    )
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.7,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
            StopCondition.TIME_BUDGET_EXHAUSTED,
            StopCondition.OBJECTIVES_COMPLETE,
        ),
    )
    orchestration.start(mission.mission_id)
    result = runner.run(mission.mission_id, max_cycles=30, max_idle_cycles=6)
    mission = orchestration.get(mission.mission_id)
    outcome = mission.outcome

    print(json.dumps({
        "target": _TARGET,
        "status": result["status"],
        "planning_state": mission.mission.state.value,
        "current_phase": mission.current_phase.value,
        "coverage": round(mission.coverage_ratio(), 4),
        "executions_used": mission.budget.executions_used,
        "executions_budget": mission.budget.executions_budget,
        "execution_exhausted": mission.budget.execution_exhausted,
        "time_exhausted": mission.budget.time_exhausted,
        "stop_condition": outcome.stop_condition if outcome else None,
        "exhausted_resource": outcome.exhausted_resource if outcome else None,
        "blocked_reason": outcome.blocked_reason if outcome else None,
        "objectives_complete": outcome.objectives_complete if outcome else None,
        "probes_executed": outcome.probes_executed if outcome else None,
        "hypotheses_deferred": sum(1 for h in mission.hypotheses if h.state.value == "deferred"),
        "ai_unavailable": outcome.ai_unavailable if outcome else None,
    }, indent=2))

    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
