#!/usr/bin/env python3
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D100, D103, E501  # diagnostic demo: single-purpose script
"""Behavioral demo: full_security_assessment against a real loopback target.

Starts a real HTTP server on 127.0.0.1:3010 and runs a full assessment through
the real orchestration + probe path. Demonstrates the corrected lifecycle:
active testing is reached (differential probes run against the loopback target)
and the terminal is honest (never a false coverage-complete while open
actionable hypotheses remain).
"""
import http.server
import json
import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
# Ensure the v7 package (src/hunterx) shadows the legacy v6 flat hunterx.py
# while keeping the repo root importable (for tests.framework).
for path in (SRC, ROOT):
    if path in sys.path:
        sys.path.remove(path)
sys.path.insert(0, ROOT)
sys.path.insert(0, SRC)

import dataclasses  # noqa: E402

from tests.framework.fakes import FakeExecutionEngine  # noqa: E402

from hunterx.application.mission_execution import MissionExecutionService  # noqa: E402
from hunterx.application.mission_orchestration import MissionOrchestrationService  # noqa: E402
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine  # noqa: E402
from hunterx.domain.mission_orchestration.enums import StopCondition  # noqa: E402
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator  # noqa: E402
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine  # noqa: E402
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine  # noqa: E402
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory  # noqa: E402


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


_TARGET = "http://127.0.0.1:18080"

_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_discovery": ("nmap",),
    "service_detection": ("nmap",),
    "technology_fingerprint": ("whatweb",),
    "endpoint_enumeration": ("httpx",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
}

_FAKE_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}]},
    "dnsx": {"records": ["api.localhost -> 127.0.0.1"]},
    "nmap": {"ports": [3010]},
    "whatweb": {"name": "httpd", "technologies": ["python-http.server"]},
    "httpx": {"endpoints": ["/", "/api"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {"findings": []},
}


def main() -> int:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_DEFAULT_CANDIDATES)
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS)),
    )
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.7,
        stop_conditions=(
            StopCondition.COVERAGE_TARGET_ACHIEVED,
            StopCondition.RESOURCE_BUDGET_EXHAUSTED,
            StopCondition.OBJECTIVES_COMPLETE,
        ),
    )
    orchestration.start(mission.mission_id)
    result = runner.run(mission.mission_id, max_cycles=40, max_idle_cycles=6)
    mission = orchestration.get(mission.mission_id)
    outcome = mission.outcome

    print(json.dumps({
        "target": _TARGET,
        "status": result["status"],
        "planning_state": mission.mission.state.value,
        "current_phase": mission.current_phase.value,
        "coverage": round(mission.coverage_ratio(), 4),
        "executions_used": mission.budget.executions_used,
        "stop_condition": outcome.stop_condition if outcome else None,
        "objectives_complete": outcome.objectives_complete if outcome else None,
        "hypotheses_total": len(mission.hypotheses),
        "hypotheses_open": outcome.hypotheses_open if outcome else None,
        "probes_executed": outcome.probes_executed if outcome else None,
        "assets": len(mission.context.assets),
        "endpoints": len(mission.context.endpoints),
        "parameters": len(mission.context.parameters),
        "attack_paths": len(mission.context.attack_paths),
        "surface_relationships": len(mission.context.surface_relationships),
        "telemetry": {
            "ai_fallbacks": (mission.telemetry_snapshots[-1].ai_fallbacks if mission.telemetry_snapshots else None),
            "ai_cooldown_events": (mission.telemetry_snapshots[-1].ai_cooldown_events if mission.telemetry_snapshots else None),
            "ai_deterministic_decisions": (mission.telemetry_snapshots[-1].ai_deterministic_decisions if mission.telemetry_snapshots else None),
            "active_tests_attempted": (mission.telemetry_snapshots[-1].active_tests_attempted if mission.telemetry_snapshots else None),
            "attack_paths_generated": (mission.telemetry_snapshots[-1].attack_paths_generated if mission.telemetry_snapshots else None),
        },
    }, indent=2))

    server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
