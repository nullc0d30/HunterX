#!/usr/bin/env python3
# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D102, D103, N801  # diagnostic tool: method/function docstrings are inline
"""Reproduce and classify the real-runtime memory runaway.

Runs a synthetic ``full_security_assessment`` mission whose tool outputs are
LARGE (multi-MB JSON blobs), so the mission aggregate grows real resident
memory — reproducing the incident class where HunterX consumed ~5.6 GiB on a
7.6 GiB host. Records cross-sectional memory telemetry each cycle (process
VmRSS/VmHWM/VmPeak, governor process-tree RSS at the same instant, Python heap,
mission-aggregate item counts and serialized bytes, model context) and prints a
classification summary.

Usage:
    python scripts/reproduce_resource_runaway.py --runaway        # caps disabled (the incident)
    python scripts/reproduce_resource_runaway.py --bounded        # caps enabled  (the fix)
    python scripts/reproduce_resource_runaway.py --analyze <file> # classify a recorded JSON-lines file

The classification answers: is the governor measurement wrong (A), does it fail
to transition (B), does memory jump before enforcement (C), is memory in
mission/model/tool state (D), or is it temporary serialization allocation (E)?
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from hunterx.application.mission_execution import MissionExecutionService  # noqa: E402
from hunterx.application.mission_orchestration import MissionOrchestrationService  # noqa: E402
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine  # noqa: E402
from hunterx.domain.mission_orchestration.enums import StopCondition  # noqa: E402
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator  # noqa: E402
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine  # noqa: E402
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine  # noqa: E402
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory  # noqa: E402
from hunterx.resource import ResourceConfig, ResourceGovernor  # noqa: E402
from hunterx.resource.sampler import ProcessTreeSampler  # noqa: E402

_TARGET = "https://juice-shop.herokuapp.com"

_DEFAULT_CANDIDATES: dict[str, tuple[str, ...]] = {
    "subdomain_enumeration": ("subfinder", "amass", "assetfinder"),
    "dns_enumeration": ("dnsx", "dig"),
    "port_discovery": ("nmap", "rustscan", "masscan"),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb", "wappalyzer"),
    "certificate_enumeration": ("certspotter", "crt.sh"),
    "endpoint_enumeration": ("httpx", "katana", "gospider"),
    "parameter_discovery": ("arjun", "x8"),
    "vulnerability_scanning": ("nuclei", "nikto"),
}

#: A large tool output blob (~2 MiB per observation) — the incident's dominant
#: in-memory consumer (tool output retained in observation content).
_BLOB_SIZE = 2_000_000
_BIG = {"blob": "x" * _BLOB_SIZE}

_FAKE_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.example.com"}], "blob": "x" * _BLOB_SIZE},
    "dnsx": {"records": ["api.example.com -> 1.2.3.4"], "blob": "x" * _BLOB_SIZE},
    "nmap": {"ports": list(range(1, 1024)), "blob": "x" * _BLOB_SIZE},
    "whatweb": {"name": "express", "technologies": ["node.js", "express"], "blob": "x" * _BLOB_SIZE},
    "httpx": {"endpoints": [f"/api/{i}" for i in range(200)], "blob": "x" * _BLOB_SIZE},
    "arjun": {"parameters": ["q", "id"], "blob": "x" * _BLOB_SIZE},
    "nuclei": {"findings": [], "blob": "x" * _BLOB_SIZE},
    "certspotter": {"certificates": ["example.com"], "blob": "x" * _BLOB_SIZE},
}


class BigOutputEngine:
    """A deterministic fake engine returning large JSON outputs."""

    def __init__(self) -> None:
        self.calls: list[object] = []

    def execute(self, context: object) -> object:
        self.calls.append(context)
        from hunterx.domain.execution import (
            ExecutionOutput,
            ExecutionResult,
            ExecutionStatus,
            OutputFormat,
        )
        from hunterx.tools.sdk.pipeline import PipelineResult
        from hunterx.tools.sdk.session import ExecutionSession

        tool_id = context.tool_id
        content = _FAKE_OUTPUTS.get(tool_id, _BIG)
        result = ExecutionResult(
            execution_id=context.execution_id,
            tool_id=tool_id,
            status=ExecutionStatus.COMPLETED,
            output=ExecutionOutput(exit_code=0, json=dict(content), formats={OutputFormat.JSON}),
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            duration_ms=5,
        )
        session = ExecutionSession.create(context)
        session.finish(result)
        return PipelineResult(result=result, session=session, attempts=1)


def build_runner(config: ResourceConfig, telemetry_file: str) -> tuple[MissionExecutionService, MissionOrchestrationService, ResourceGovernor, BigOutputEngine]:
    governor = ResourceGovernor(config, sampler=ProcessTreeSampler())
    governor.start_monitoring()
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_DEFAULT_CANDIDATES)
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
        resource_config=config,
    )
    engine = BigOutputEngine()
    runner = MissionExecutionService(orchestration=orchestration, planning=planning, execution_engine=engine, governor=governor)
    return runner, orchestration, governor, engine


def run_mission(config: ResourceConfig, telemetry_file: str, *, deadline_s: float = 0.0) -> dict[str, object]:
    runner, orchestration, governor, engine = build_runner(config, telemetry_file)
    mission = orchestration.create_mission(objective="full_security_assessment", target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        resource_budget=2000,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    if deadline_s > 0:
        # Pre-register the mission with a hard deadline so the reproduction is
        # always bounded (start_mission is idempotent; run() keeps the deadline).
        governor.start_mission(mission.mission_id, deadline_s=deadline_s)
    result = runner.run(mission.mission_id, max_cycles=300, max_idle_cycles=60)
    governor.stop_monitoring()
    return {
        "status": result["status"],
        "resource_state": result["resource"]["state"],
        "cycles_run": result["cycles_run"],
        "executions_used": result["executions_used"],
        "observations": result["observations"],
        "tool_executions": result["tool_executions"],
        "outcome": mission.outcome.stop_condition if mission.outcome else None,
        "telemetry_file": telemetry_file,
        "governor": governor.report(),
    }


def classify(records: list[dict[str, object]]) -> dict[str, object]:
    """Classify the failure from the recorded telemetry (data-driven)."""
    if not records:
        return {"records": 0}
    last = records[-1]
    first = records[0]

    def f(key: str, record: dict[str, object]) -> float:
        return float(record.get(key, 0.0) or 0.0)

    governor_rss = f("process_tree_rss_mb", last)
    vmrss = f("vmrss_mb", last)
    baseline = f("vmrss_mb", first)
    peak_gov = max(f("process_tree_rss_mb", r) for r in records)
    peak_vmrss = max(f("vmrss_mb", r) for r in records)
    agg_bytes = float(last.get("mission_aggregate_approx_bytes", 0.0) or 0.0)
    heap = f("heap_current_mb", last)
    mission_growth_mb = max(0.0, peak_vmrss - baseline)
    agg_mb = agg_bytes / 1048576.0

    classes: list[str] = []
    if governor_rss < vmrss * 0.8 and vmrss > 1.0:
        classes.append("A: governor measurement << /proc VmRSS (sampler/accounting bug)")
    governor_state = str(last.get("governor", {}).get("state", "normal"))
    if vmrss > 0 and "governor" in last and last["governor"].get("ceiling_mb", 0) and vmrss > float(last["governor"]["ceiling_mb"]) and governor_state != "emergency":
        classes.append("B: governor saw > ceiling but did not transition (enforcement gap)")
    if peak_vmrss > 0 and peak_gov > 0 and peak_gov < peak_vmrss * 0.8:
        classes.append("A: governor peak measurement << /proc peak VmRSS (sampler bug)")
    if vmrss > 0 and governor_rss > 0 and abs(governor_rss - vmrss) / max(vmrss, 1.0) < 0.25:
        classes.append("(governor tracks /proc VmRSS within 25%)")
    if mission_growth_mb > 50 and agg_mb > 0 and mission_growth_mb > agg_mb * 1.5 + 50:
        classes.append("E: mission RSS growth far exceeds retained aggregate bytes (temporary allocation during analysis/serialization)")
    elif mission_growth_mb > 50 and agg_mb > 0 and agg_mb >= mission_growth_mb * 0.6:
        classes.append("D: mission RSS growth primarily retained mission/model/tool state (bounded-state incomplete)")
    elif mission_growth_mb > 50:
        classes.append("(mission RSS growth not yet attributed)")
    else:
        classes.append("(mission RSS growth bounded below 50 MB)")
    if not classes:
        classes.append("unclassified: inspect records")
    return {
        "records": len(records),
        "first": {"vmrss_mb": f("vmrss_mb", first), "governor_rss_mb": f("process_tree_rss_mb", first), "state": first.get("governor", {}).get("state")},
        "last": {"vmrss_mb": vmrss, "vmhwm_mb": f("vmhwm_mb", last), "vmpeak_mb": f("vmpeak_mb", last), "governor_rss_mb": governor_rss, "state": governor_state},
        "peak": {"vmrss_mb": peak_vmrss, "governor_rss_mb": peak_gov},
        "mission_growth_mb": mission_growth_mb,
        "mission_aggregate_approx_bytes": int(agg_bytes),
        "heap_current_mb": heap,
        "classes": classes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runaway", action="store_true", help="reproduce the incident (byte caps disabled)")
    parser.add_argument("--bounded", action="store_true", help="run with byte caps enabled (the fix)")
    parser.add_argument("--analyze", metavar="FILE", help="classify a recorded JSON-lines telemetry file")
    parser.add_argument("--ceiling-mb", type=float, default=1200.0, help="governor ceiling for the reproduction")
    parser.add_argument("--deadline-s", type=float, default=90.0, help="hard mission deadline so the run always terminates")
    args = parser.parse_args()

    if args.analyze:
        records: list[dict[str, object]] = []
        with open(args.analyze, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        print(json.dumps(classify(records), indent=2))
        return 0

    telemetry_file = os.path.join(tempfile.gettempdir(), "hunterx-resource-telemetry.jsonl")
    if os.path.exists(telemetry_file):
        os.remove(telemetry_file)

    if args.runaway:
        # Incident reproduction: byte caps effectively disabled, tracemalloc on.
        config = ResourceConfig(
            memory_ceiling_mb=args.ceiling_mb,
            max_observation_content_bytes=100 * 1024 * 1024,
            max_aggregate_state_bytes=100 * 1024 * 1024 * 1024,
            max_model_context_bytes=50 * 1024 * 1024,
            telemetry_file=telemetry_file,
            telemetry_tracemalloc=True,
            telemetry_interval_s=0.2,
            watchdog_interval_s=0.2,
        )
    else:
        # The fix: bounded content/aggregate bytes.
        config = ResourceConfig(
            memory_ceiling_mb=args.ceiling_mb,
            max_observation_content_bytes=262144,
            max_aggregate_state_bytes=1073741824,
            max_model_context_bytes=1048576,
            telemetry_file=telemetry_file,
            telemetry_tracemalloc=True,
            telemetry_interval_s=0.2,
            watchdog_interval_s=0.2,
        )

    summary = run_mission(config, telemetry_file, deadline_s=args.deadline_s)
    records: list[dict[str, object]] = []
    if os.path.exists(telemetry_file):
        with open(telemetry_file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    classification = classify(records)
    print(json.dumps({"summary": summary, "classification": classification}, indent=2), flush=True)
    print(f"\ntelemetry: {telemetry_file}", flush=True)
    return 0


if __name__ == "__main__":
    import traceback

    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001
        traceback.print_exc()
        raise SystemExit(1) from error
