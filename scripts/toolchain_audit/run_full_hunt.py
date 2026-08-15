"""Drive the full adaptive hunt in a single process against the real target.

Captures every cycle, decision, tool execution, observation and failure so the
final rollout telemetry is complete and persistent.
"""
from __future__ import annotations

import json
import os
import sys

os.environ.pop("HUNTERX_DATABASE_URL", None)
os.environ.pop("HUNTERX_DB_URL", None)

from hunterx.platform import build_platform  # noqa: E402


def main() -> None:
    plat = build_platform()
    mission_service = plat.mission_orchestration_service
    execution = plat.mission_execution_service
    dashboard = plat.mission_dashboard_service

    target = "https://juice-shop.herokuapp.com"
    objective = "full_security_assessment"

    mission = mission_service.create_mission(objective=objective, target=target)
    mid = mission.mission_id
    print("MISSION_ID:", mid)

    # Start (DISCOVERY phase)
    try:
        mission_service.start(mid)
    except Exception as exc:  # noqa: BLE001
        print("start:", type(exc).__name__, str(exc)[:120])

    # Run the adaptive loop (persistent in this process)
    run = execution.run(mid, max_cycles=16, max_idle_cycles=3)
    print("RUN_SUMMARY:", json.dumps({
        "cycles_run": run.get("cycles_run"),
        "tool_executions": run.get("tool_executions"),
        "observations": run.get("observations"),
        "decisions": run.get("decisions"),
        "coverage_ratio": run.get("coverage_ratio"),
        "status": run.get("status"),
        "planning_state": run.get("planning_state"),
    }, indent=1))

    # Re-run for reassessment until it settles (adaptive REPLAN)
    for i in range(2, 7):
        again = execution.run(mid, max_cycles=4, max_idle_cycles=2)
        if again.get("tool_executions", 0) == 0 and again.get("observations", 0) == 0:
            print(f"reassessment cycle {i}: idle, stopping")
            break
        print(f"reassessment cycle {i}: exec={again.get('tool_executions')} obs={again.get('observations')} decisions={again.get('decisions')} cov={again.get('coverage_ratio')}")

    # Persist every artifact
    overview = dashboard.overview(mid)
    surface = dashboard.attack_surface(mid)
    coverage = dashboard.coverage(mid)
    findings = dashboard.findings(mid)
    evidence = dashboard.evidence(mid)
    paths = dashboard.attack_paths(mid)
    timeline = dashboard.timeline(mid)

    out = {
        "mission_id": mid,
        "run_summary": run,
        "overview": overview,
        "surface": surface,
        "coverage": coverage,
        "findings": findings,
        "evidence": evidence,
        "attack_paths": paths,
        "timeline": timeline,
    }
    base = "/home/nc/hunterx/HunterX/artifacts/final-rollout"
    import glob
    ts_dirs = sorted(glob.glob(f"{base}/*/"))
    ts = ts_dirs[-1].split("/")[-2] if ts_dirs else "manual"
    tele = f"{base}/{ts}/telemetry"
    json.dump(out, open(f"{tele}/mission.json", "w"), indent=2, default=str)
    print("WROTE mission.json")

    # dump cycles detail
    json.dump(run.get("cycles", []), open(f"{tele}/cycles.json", "w"), indent=2, default=str)
    print("WROTE cycles.json")


if __name__ == "__main__":
    main()
