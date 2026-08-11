# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Default CLI commands.

Foundation-level commands that work without business logic: version, help,
config snapshot, platform composition status. Mission/scan commands arrive
with the engine wiring in later sprints.
"""

from __future__ import annotations

from typing import Any

import hunterx
from hunterx.cli.app import CliApplication


def register_default_commands(app: CliApplication, platform: Any | None = None) -> None:
    """Register the foundation default commands on ``app``.

    Args:
        app: the CLI application to register commands on.
        platform: an optional composed platform; when provided, the
            ``platform`` command reports composition status.

    """
    if platform is None:
        from hunterx.platform import build_platform

        # The CLI persists missions to the configured database so command
        # invocations can be chained (mission create -> mission start) and
        # survive process restarts.
        platform = build_platform(persistence=True)

    def _version(_argv: list[str]) -> int:
        print(f"HunterX v{hunterx.__version__}")
        return 0

    def _help(argv: list[str]) -> int:
        print(app.help_text())
        return 0

    def _config(_argv: list[str]) -> int:
        from hunterx.config.loader import load_default_settings

        settings = load_default_settings()
        print(app.renderer.render(settings.model_dump(mode="json"), fmt="json"))
        return 0

    def _platform(_argv: list[str]) -> int:
        from hunterx.platform.platform import Platform

        assert isinstance(platform, Platform)  # nosec B101  # platform is always built
        payload = {
            "environment": platform.settings.environment,
            "cache_backend": platform.settings.cache.backend,
            "queue_backend": platform.settings.queue.backend,
            "repositories": {
                role: type(repository).__name__ for role, repository in platform.repositories.items()
            },
            "facades": {
                "tip": platform.tip.__class__.__name__,
                "execution_engine": platform.execution_engine.__class__.__name__,
                "tool_factory": platform.tool_factory.__class__.__name__,
                "mission_planning": platform.mission_planning.__class__.__name__,
            },
            "services": {
                "missions": platform.mission_service.__class__.__name__,
                "findings": platform.finding_service.__class__.__name__,
                "reports": platform.report_service.__class__.__name__,
                "tool_factory": platform.tool_factory_service.__class__.__name__,
                "mission_planning": platform.mission_planning_service.__class__.__name__,
                "adaptive_mission_planning": platform.adaptive_mission_planning_service.__class__.__name__,
                "mission_orchestration": platform.mission_orchestration_service.__class__.__name__,
            },
        }
        print(app.renderer.render(payload, fmt="json"))
        return 0

    app.registry.register("version", _version, help_text="Show the platform version")
    app.registry.register("help", _help, help_text="Show command help")
    app.registry.register("config", _config, help_text="Show resolved configuration")
    app.registry.register("platform", _platform, help_text="Show platform composition status")
    _register_adaptive_mission_commands(app, platform)
    _register_mission_orchestration_commands(app, platform)
    _register_hunt_commands(app, platform)
    _register_finding_commands(app, platform)
    _register_report_commands(app, platform)
    _register_target_memory_commands(app, platform)
    _register_toolchain_commands(app, platform)


def _require_finding_id(argv: list[str]) -> str:
    """Return the first ``argv`` entry as a finding id or exit."""
    if not argv:
        raise SystemExit("usage: hunterx finding <command> <finding_id>")
    return argv[0]


def _register_finding_commands(app: CliApplication, platform: Any) -> None:
    """Register the vulnerability finding orchestration commands.

    Commands (Sprint 028): ``finding create``, ``finding list``, ``finding
    show``, ``finding evidence``, ``finding validate``, ``finding proof``,
    ``finding poc``, ``finding replay``, ``finding explain`` and ``finding
    report-ready``. No unsafe unrestricted execution is exposed through the
    CLI: validation runs only ranked, scope- and safety-checked strategies.
    """

    def _finding_create(argv: list[str]) -> int:
        service = platform.vulnerability_finding_service
        finding = service.create_finding(
            mission_id=argv[0] if argv else "",
            target_id=argv[1] if len(argv) > 1 else "",
            vulnerability_class=argv[2] if len(argv) > 2 else "unknown_behavior",
            title=argv[3] if len(argv) > 3 else "",
            description=argv[4] if len(argv) > 4 else "",
            severity=argv[5] if len(argv) > 5 else "info",
            tool=argv[6] if len(argv) > 6 else "cli",
        )
        print(app.renderer.render(finding, fmt="json"))
        return 0

    def _finding_list(argv: list[str]) -> int:
        mission_id = argv[0] if argv else ""
        findings = platform.vulnerability_finding_service.list_findings(mission_id)
        print(app.renderer.render(findings, fmt="json"))
        return 0

    def _finding_show(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        finding = platform.vulnerability_finding_service.get_finding(finding_id)
        print(app.renderer.render(finding, fmt="json"))
        return 0

    def _finding_evidence(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        assessment = platform.vulnerability_finding_service.assess_evidence(finding_id)
        print(app.renderer.render(assessment, fmt="json"))
        return 0

    def _finding_validate(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        result = platform.vulnerability_finding_service.validate_finding(finding_id)
        print(app.renderer.render(result, fmt="json"))
        return 0

    def _finding_poc(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        poc_format = argv[1] if len(argv) > 1 else "http_request"
        poc = platform.vulnerability_finding_service.generate_poc(finding_id, poc_format=poc_format)
        print(app.renderer.render(poc, fmt="json"))
        return 0

    def _finding_proof(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        poc = platform.vulnerability_finding_service.generate_poc(finding_id, poc_format="http_request")
        print(app.renderer.render(poc, fmt="json"))
        return 0

    def _finding_replay(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        poc_id = argv[1] if len(argv) > 1 else ""
        confirmed = len(argv) > 2 and argv[2].lower() in ("1", "true", "yes")
        if not poc_id:
            raise SystemExit("usage: hunterx finding replay <finding_id> <poc_id> [confirmed]")
        replay = platform.vulnerability_finding_service.replay_poc(
            finding_id,
            poc_id,
            outcome={"confirmed": confirmed, "target": argv[3] if len(argv) > 3 else ""},
        )
        print(app.renderer.render(replay, fmt="json"))
        return 0

    def _finding_explain(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        explanation = platform.vulnerability_finding_service.get_confidence_explanation(finding_id)
        print(app.renderer.render(explanation, fmt="json"))
        return 0

    def _finding_report_ready(argv: list[str]) -> int:
        finding_id = _require_finding_id(argv)
        readiness = platform.vulnerability_finding_service.get_report_readiness(finding_id)
        print(app.renderer.render(readiness, fmt="json"))
        return 0

    app.registry.register("finding create", _finding_create, help_text="Create an orchestrated finding")
    app.registry.register("finding list", _finding_list, help_text="List findings for a mission")
    app.registry.register("finding show", _finding_show, help_text="Show an orchestrated finding")
    app.registry.register("finding evidence", _finding_evidence, help_text="Assess evidence and gaps for a finding")
    app.registry.register("finding validate", _finding_validate, help_text="Execute safe validation for a finding")
    app.registry.register("finding poc", _finding_poc, help_text="Generate a minimal, sanitized PoC")
    app.registry.register("finding proof", _finding_proof, help_text="Generate a proof PoC for a finding")
    app.registry.register("finding replay", _finding_replay, help_text="Replay a PoC under controlled conditions")
    app.registry.register("finding explain", _finding_explain, help_text="Explain the evidence-driven confidence")
    app.registry.register("finding report-ready", _finding_report_ready, help_text="Show the report-readiness checklist")


def _register_report_commands(app: CliApplication, platform: Any) -> None:
    """Register the professional reporting commands.

    Commands (Sprint 029): ``report list``, ``report show``, ``report
    preview``, ``report validate``, ``report generate``, ``report export``,
    ``report evidence``, ``report timeline``, ``report remediation``,
    ``report retest`` and ``report sarif``.
    """

    def _service() -> Any:
        return platform.professional_reporting_service

    def _finding_id(argv: list[str]) -> str:
        if not argv:
            raise SystemExit("usage: hunterx report <command> <finding_id|report_id>")
        return argv[0]

    def _report_list(argv: list[str]) -> int:
        finding_id = _finding_id(argv)
        reports = _service().list_reports(finding_id)
        print(app.renderer.render(reports, fmt="json"))
        return 0

    def _report_show(argv: list[str]) -> int:
        report_id = _finding_id(argv)
        report = _service().get_report(report_id)
        print(app.renderer.render(report, fmt="json"))
        return 0

    def _report_preview(argv: list[str]) -> int:
        template = argv[0] if argv else "pentest"
        preview = _service().report_template(template)
        print(app.renderer.render(preview, fmt="json"))
        return 0

    def _report_validate(argv: list[str]) -> int:
        report_id = _finding_id(argv)
        qa = _service().qa_report(report_id)
        print(app.renderer.render(qa, fmt="json"))
        return 0

    def _report_generate(argv: list[str]) -> int:
        finding_id = _finding_id(argv)
        template = argv[1] if len(argv) > 1 else "pentest"
        report = _service().generate_report(finding_id, template=template)
        print(app.renderer.render(report, fmt="json"))
        return 0

    def _report_export(argv: list[str]) -> int:
        report_id = _finding_id(argv)
        fmt = argv[1] if len(argv) > 1 else "markdown"
        exported = _service().export_report(report_id, fmt=fmt)
        print(app.renderer.render(exported, fmt="json"))
        return 0

    def _report_evidence(argv: list[str]) -> int:
        finding_id = _finding_id(argv)
        bundle = _service().evidence_bundle(finding_id)
        print(app.renderer.render(bundle, fmt="json"))
        return 0

    def _report_timeline(argv: list[str]) -> int:
        finding_id = _finding_id(argv)
        timeline = _service().finding_timeline(finding_id)
        print(app.renderer.render(timeline, fmt="json"))
        return 0

    def _report_remediation(argv: list[str]) -> int:
        finding_id = _finding_id(argv)
        remediation = _service().remediate(finding_id)
        print(app.renderer.render(remediation, fmt="json"))
        return 0

    def _report_retest(argv: list[str]) -> int:
        finding_id = _finding_id(argv)
        retest = _service().retest(finding_id)
        print(app.renderer.render(retest, fmt="json"))
        return 0

    def _report_sarif(argv: list[str]) -> int:
        report_id = _finding_id(argv)
        sarif = _service().export_sarif(report_id)
        print(app.renderer.render(sarif, fmt="json"))
        return 0

    app.registry.register("report list", _report_list, help_text="List professional reports for a finding")
    app.registry.register("report show", _report_show, help_text="Show a professional report and its package")
    app.registry.register("report preview", _report_preview, help_text="Preview a report template")
    app.registry.register("report validate", _report_validate, help_text="Run report QA validation")
    app.registry.register("report generate", _report_generate, help_text="Generate a professional report package")
    app.registry.register("report export", _report_export, help_text="Export a report (markdown/html/json/sarif/pdf/package)")
    app.registry.register("report evidence", _report_evidence, help_text="Show the evidence bundle for a finding")
    app.registry.register("report timeline", _report_timeline, help_text="Show the finding timeline")
    app.registry.register("report remediation", _report_remediation, help_text="Build a remediation plan")
    app.registry.register("report retest", _report_retest, help_text="Build a retest plan")
    app.registry.register("report sarif", _report_sarif, help_text="Export a report as SARIF")


def _register_adaptive_mission_commands(app: CliApplication, platform: Any) -> None:
    """Register the adaptive mission & attack-path planning commands.

    Commands (Sprint 027): ``mission plan``, ``mission status``,
    ``mission replan``, ``mission pause``, ``mission resume``,
    ``mission paths`` and ``mission explain``.
    """

    def _require_mission_id(argv: list[str]) -> str:
        if not argv:
            raise SystemExit("usage: hunterx mission <command> <mission_id>")
        return argv[0]

    def _mission_plan(argv: list[str]) -> int:
        service = platform.adaptive_mission_planning_service
        objective = argv[0] if argv else "attack_surface_discovery"
        target = argv[1] if len(argv) > 1 else ""
        mission = service.create_mission(objective=objective, target=target)
        print(app.renderer.render(mission.to_dict(), fmt="json"))
        return 0

    def _mission_status(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = platform.adaptive_mission_planning_service.status(mission_id)
        print(app.renderer.render(mission.to_dict(), fmt="json"))
        return 0

    def _mission_replan(argv: list[str]) -> int:
        from hunterx.domain.adaptive_mission_planning.enums import ReplanTrigger

        mission_id = _require_mission_id(argv)
        trigger = argv[1] if len(argv) > 1 else "new_asset_discovered"
        delta = platform.adaptive_mission_planning_service.replan(
            mission_id,
            trigger=ReplanTrigger(trigger),
        )
        print(app.renderer.render(delta.to_dict(), fmt="json"))
        return 0

    def _mission_pause(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = platform.adaptive_mission_planning_service.pause(mission_id)
        print(app.renderer.render(mission.to_dict(), fmt="json"))
        return 0

    def _mission_resume(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = platform.adaptive_mission_planning_service.resume(mission_id)
        print(app.renderer.render(mission.to_dict(), fmt="json"))
        return 0

    def _mission_paths(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        paths = platform.adaptive_mission_planning_service.attack_paths(mission_id)
        print(app.renderer.render([path.to_dict() for path in paths], fmt="json"))
        return 0

    def _mission_explain(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        explanation = platform.adaptive_mission_planning_service.explain_next(mission_id)
        print(app.renderer.render(explanation, fmt="json"))
        return 0

    app.registry.register("mission plan", _mission_plan, help_text="Create an adaptive mission and print the plan")
    app.registry.register("mission status", _mission_status, help_text="Show adaptive mission status")
    app.registry.register("mission replan", _mission_replan, help_text="Replan an adaptive mission")
    app.registry.register("mission pause", _mission_pause, help_text="Pause an adaptive mission")
    app.registry.register("mission resume", _mission_resume, help_text="Resume an adaptive mission")
    app.registry.register("mission paths", _mission_paths, help_text="Show attack paths for an adaptive mission")
    app.registry.register("mission explain", _mission_explain, help_text="Explain the next best action for a mission")


def _register_hunt_commands(app: CliApplication, platform: Any) -> None:
    """Register the full-spectrum hunt commands (Sprint 033).

    Commands: ``hunt`` (create+start a mission), ``hunt status``, ``hunt
    surface``, ``hunt coverage``, ``hunt findings``, ``hunt evidence``, ``hunt
    proofs``, ``hunt paths`` and ``hunt timeline``. They wrap the autonomous
    mission orchestration and the mission dashboard services so an operator can
    drive and inspect a full-spectrum security-assessment mission from the CLI.
    """

    def _orchestration() -> Any:
        return platform.mission_orchestration_service

    def _dashboard() -> Any:
        return platform.mission_dashboard_service

    def _require_mission_id(argv: list[str]) -> str:
        if not argv:
            raise SystemExit("usage: hunterx hunt <command> <mission_id>")
        return argv[0]

    def _hunt(argv: list[str]) -> int:
        objective = argv[0] if argv else "full_security_assessment"
        target = argv[1] if len(argv) > 1 else ""
        mission = _orchestration().create_mission(objective=objective, target=target)
        _orchestration().start(mission.mission_id)
        overview = _dashboard().overview(mission.mission_id)
        print(app.renderer.render(overview, fmt="json"))
        return 0

    def _hunt_status(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().overview(mission_id), fmt="json"))
        return 0

    def _hunt_surface(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().attack_surface(mission_id), fmt="json"))
        return 0

    def _hunt_coverage(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().coverage(mission_id), fmt="json"))
        return 0

    def _hunt_findings(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().findings(mission_id), fmt="json"))
        return 0

    def _hunt_evidence(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().evidence(mission_id), fmt="json"))
        return 0

    def _hunt_proofs(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().proofs(mission_id), fmt="json"))
        return 0

    def _hunt_paths(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().attack_paths(mission_id), fmt="json"))
        return 0

    def _hunt_timeline(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_dashboard().timeline(mission_id), fmt="json"))
        return 0

    app.registry.register("hunt", _hunt, help_text="Create and start a full-spectrum hunt mission")
    app.registry.register("hunt status", _hunt_status, help_text="Show the mission overview")
    app.registry.register("hunt surface", _hunt_surface, help_text="Show the unified attack-surface view")
    app.registry.register("hunt coverage", _hunt_coverage, help_text="Show mission coverage")
    app.registry.register("hunt findings", _hunt_findings, help_text="Show mission findings")
    app.registry.register("hunt evidence", _hunt_evidence, help_text="Show mission evidence")
    app.registry.register("hunt proofs", _hunt_proofs, help_text="Show mission proofs")
    app.registry.register("hunt paths", _hunt_paths, help_text="Show mission attack paths")
    app.registry.register("hunt timeline", _hunt_timeline, help_text="Show mission timeline")


def _register_mission_orchestration_commands(app: CliApplication, platform: Any) -> None:
    """Register the autonomous mission orchestration commands.

    Commands (Sprint 032): ``mission create``, ``mission start``,
    ``mission status``, ``mission pause``, ``mission resume``,
    ``mission cancel``, ``mission finalize``, ``mission timeline``,
    ``mission decisions``, ``mission hypotheses``, ``mission findings``,
    ``mission attack-paths``, ``mission coverage`` and ``mission tools``.
    """

    def _service() -> Any:
        return platform.mission_orchestration_service

    def _require_mission_id(argv: list[str]) -> str:
        if not argv:
            raise SystemExit("usage: hunterx mission <command> <mission_id>")
        return argv[0]

    def _mission_create(argv: list[str]) -> int:
        objective = argv[0] if argv else "full_security_assessment"
        target = argv[1] if len(argv) > 1 else ""
        mission = _service().create_mission(objective=objective, target=target)
        print(app.renderer.render(mission.to_dict(), fmt="json"))
        return 0

    def _mission_start(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().start(mission_id), fmt="json"))
        return 0

    def _mission_status(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().status(mission_id), fmt="json"))
        return 0

    def _mission_pause(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().pause(mission_id), fmt="json"))
        return 0

    def _mission_resume(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().resume(mission_id), fmt="json"))
        return 0

    def _mission_cancel(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().cancel(mission_id), fmt="json"))
        return 0

    def _mission_finalize(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().finalize(mission_id), fmt="json"))
        return 0

    def _mission_timeline(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = _service().get(mission_id)
        print(app.renderer.render(mission.context.history, fmt="json"))
        return 0

    def _mission_decisions(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = _service().get(mission_id)
        print(app.renderer.render([decision.to_dict() for decision in mission.decisions], fmt="json"))
        return 0

    def _mission_hypotheses(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = _service().get(mission_id)
        print(app.renderer.render([hypothesis.to_dict() for hypothesis in mission.hypotheses], fmt="json"))
        return 0

    def _mission_findings(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = _service().get(mission_id)
        print(app.renderer.render(mission.context.findings, fmt="json"))
        return 0

    def _mission_attack_paths(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = _service().get(mission_id)
        print(app.renderer.render(mission.context.attack_paths, fmt="json"))
        return 0

    def _mission_coverage(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        print(app.renderer.render(_service().coverage(mission_id), fmt="json"))
        return 0

    def _mission_tools(argv: list[str]) -> int:
        mission_id = _require_mission_id(argv)
        mission = _service().get(mission_id)
        print(app.renderer.render(mission.context.tool_executions, fmt="json"))
        return 0

    app.registry.register("mission create", _mission_create, help_text="Create an autonomous mission")
    app.registry.register("mission start", _mission_start, help_text="Start an autonomous mission run")
    app.registry.register("mission status", _mission_status, help_text="Show autonomous mission status")
    app.registry.register("mission pause", _mission_pause, help_text="Pause an autonomous mission")
    app.registry.register("mission resume", _mission_resume, help_text="Resume an autonomous mission")
    app.registry.register("mission cancel", _mission_cancel, help_text="Cancel an autonomous mission")
    app.registry.register("mission finalize", _mission_finalize, help_text="Finalize an autonomous mission")
    app.registry.register("mission timeline", _mission_timeline, help_text="Show autonomous mission timeline")
    app.registry.register("mission decisions", _mission_decisions, help_text="Show autonomous mission decisions")
    app.registry.register("mission hypotheses", _mission_hypotheses, help_text="Show autonomous mission hypotheses")
    app.registry.register("mission findings", _mission_findings, help_text="Show autonomous mission findings")
    app.registry.register("mission attack-paths", _mission_attack_paths, help_text="Show autonomous mission attack paths")
    app.registry.register("mission coverage", _mission_coverage, help_text="Show autonomous mission coverage")
    app.registry.register("mission tools", _mission_tools, help_text="Show autonomous mission tool executions")


def _register_target_memory_commands(app: CliApplication, platform: Any) -> None:
    """Register the target memory & campaign intelligence commands.

    Commands (Sprint 030): ``target memory``, ``target snapshot``, ``target
    diff``, ``target changes``, ``target history``, ``target coverage``,
    ``target gaps``, ``target risk``, ``target revalidate``, ``campaign list``,
    ``campaign show`` and ``campaign intelligence``.
    """

    def _require_target_id(argv: list[str]) -> str:
        if not argv:
            raise SystemExit("usage: hunterx target <command> <target_id>")
        return argv[0]

    def _target_memory(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        memory = platform.target_memory_query_service.memory(target_id)
        print(app.renderer.render(memory.to_dict(), fmt="json"))
        return 0

    def _target_snapshot(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        mission_id = argv[1] if len(argv) > 1 else ""
        snapshot = platform.target_memory_service.create_snapshot(target_id, mission_id=mission_id)
        print(app.renderer.render(snapshot.with_state(), fmt="json"))
        return 0

    def _target_diff(argv: list[str]) -> int:
        if len(argv) < 2:
            raise SystemExit("usage: hunterx target diff <snapshot_a> <snapshot_b> [baseline]")
        diff = platform.target_memory_service.diff_snapshots(argv[0], argv[1], baseline_id=argv[2] if len(argv) > 2 else "")
        print(app.renderer.render(diff.to_dict(), fmt="json"))
        return 0

    def _target_changes(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        changes = platform.target_memory_query_service.changes(target_id)
        print(app.renderer.render(changes, fmt="json"))
        return 0

    def _target_history(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        history = [obs.to_dict() for obs in platform.target_memory_query_service.observation_history(target_id)]
        print(app.renderer.render(history, fmt="json"))
        return 0

    def _target_coverage(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        coverage = platform.target_memory_query_service.coverage(target_id)
        print(app.renderer.render(coverage, fmt="json"))
        return 0

    def _target_gaps(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        gaps = [gap.to_dict() for gap in platform.target_memory_query_service.coverage_gaps(target_id)]
        print(app.renderer.render(gaps, fmt="json"))
        return 0

    def _target_risk(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        risk = [entry.to_dict() for entry in platform.target_memory_query_service.risk_history(target_id)]
        print(app.renderer.render(risk, fmt="json"))
        return 0

    def _target_revalidate(argv: list[str]) -> int:
        target_id = _require_target_id(argv)
        plan = platform.target_memory_service.build_revalidation_plan(target_id)
        print(app.renderer.render(plan.to_dict(), fmt="json"))
        return 0

    def _campaign_list(argv: list[str]) -> int:
        campaigns = [campaign.to_dict() for campaign in platform.target_memory_query_service.campaigns()]
        print(app.renderer.render(campaigns, fmt="json"))
        return 0

    def _campaign_show(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx campaign show <campaign_id>")
        campaign = platform.target_memory_query_service.campaign(argv[0])
        if campaign is None:
            raise SystemExit(f"campaign {argv[0]} not found")
        print(app.renderer.render(campaign.to_dict(), fmt="json"))
        return 0

    def _campaign_intelligence(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx campaign intelligence <campaign_id>")
        intelligence = platform.target_memory_query_service.campaign_intelligence(argv[0])
        print(app.renderer.render(intelligence.to_dict(), fmt="json"))
        return 0

    app.registry.register("target memory", _target_memory, help_text="Show target memory")
    app.registry.register("target snapshot", _target_snapshot, help_text="Create and show a target snapshot")
    app.registry.register("target diff", _target_diff, help_text="Compute a deterministic snapshot diff")
    app.registry.register("target changes", _target_changes, help_text="Show detected target changes")
    app.registry.register("target history", _target_history, help_text="Show observation history")
    app.registry.register("target coverage", _target_coverage, help_text="Show coverage memory")
    app.registry.register("target gaps", _target_gaps, help_text="Show coverage gaps")
    app.registry.register("target risk", _target_risk, help_text="Show risk history")
    app.registry.register("target revalidate", _target_revalidate, help_text="Build a revalidation plan")
    app.registry.register("campaign list", _campaign_list, help_text="List campaigns")
    app.registry.register("campaign show", _campaign_show, help_text="Show a campaign")
    app.registry.register("campaign intelligence", _campaign_intelligence, help_text="Show campaign intelligence")


def _register_toolchain_commands(app: CliApplication, platform: Any) -> None:
    """Register the full-toolchain command group (Sprint 031).

    Commands: ``tools list``, ``tools show``, ``tools capabilities``,
    ``tools health``, ``tools versions``, ``tools execute``,
    ``tools inspect-result``, ``tools parse``, ``tools normalize``,
    ``tools chain`` and ``tools recommend``. Every command is a read or a
    guarded, structured execution — targets are typed arguments, never shell
    fragments.
    """

    def _service() -> Any:
        return platform.toolchain_service

    def _flag(argv: list[str], name: str, default: str = "") -> str:
        for index, part in enumerate(argv):
            if part == name and index + 1 < len(argv):
                return argv[index + 1]
        return default

    def _json_flag(argv: list[str], name: str) -> dict[str, Any]:
        import json

        value = _flag(argv, name, "")
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{name} must be valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise SystemExit(f"{name} must be a JSON object")
        return parsed

    def _tools_list(_argv: list[str]) -> int:
        print(app.renderer.render(_service().list_tools(), fmt="json"))
        return 0

    def _tools_show(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools show <tool_id>")
        print(app.renderer.render(_service().show_tool(argv[0]), fmt="json"))
        return 0

    def _tools_capabilities(argv: list[str]) -> int:
        if argv:
            print(app.renderer.render(_service().tool_capabilities(argv[0]), fmt="json"))
        else:
            print(app.renderer.render(_service().capabilities(), fmt="json"))
        return 0

    def _tools_health(argv: list[str]) -> int:
        print(app.renderer.render(_service().health(argv[0] if argv else ""), fmt="json"))
        return 0

    def _tools_versions(argv: list[str]) -> int:
        print(app.renderer.render(_service().versions(argv[0] if argv else ""), fmt="json"))
        return 0

    def _tools_execute(argv: list[str]) -> int:
        if len(argv) < 2:
            raise SystemExit("usage: hunterx tools execute <tool_id> <target> [--parameters JSON] [--mission <id>]")
        tool_id, target = argv[0], argv[1]
        parameters = _json_flag(argv, "--parameters")
        mission_id = _flag(argv, "--mission")
        result = _service().execute(
            tool_id,
            target,
            parameters=parameters,
            mission_id=mission_id,
        )
        print(app.renderer.render(result, fmt="json"))
        return 0

    def _tools_inspect_result(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools inspect-result <execution_id>")
        print(app.renderer.render(_service().inspect_result(argv[0]), fmt="json"))
        return 0

    def _tools_parse(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools parse <tool_id> --raw <output|@file>")
        tool_id = argv[0]
        raw = _flag(argv, "--raw", "")
        if raw.startswith("@"):
            import pathlib

            raw = pathlib.Path(raw[1:]).read_text(encoding="utf-8")
        if not raw:
            raise SystemExit("usage: hunterx tools parse <tool_id> --raw <output|@file>")
        print(app.renderer.render(_service().parse(tool_id, raw), fmt="json"))
        return 0

    def _tools_normalize(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools normalize <tool_id> --records <JSON>")
        tool_id = argv[0]
        records = _json_flag(argv, "--records")
        print(app.renderer.render(_service().normalize(tool_id, [records]), fmt="json"))
        return 0

    def _tools_chain(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools chain <objective> --capabilities a,b,c")
        objective = argv[0]
        capabilities = [item.strip() for item in _flag(argv, "--capabilities", "").split(",") if item.strip()]
        mission_id = _flag(argv, "--mission")
        print(app.renderer.render(_service().chain(objective, capabilities, mission_id=mission_id), fmt="json"))
        return 0

    def _tools_chain_execute(argv: list[str]) -> int:
        if len(argv) < 3:
            raise SystemExit(
                "usage: hunterx tools chain-execute <objective> <target> --capabilities a,b,c "
                "[--parameters JSON] [--mission <id>] [--timeout <s>] [--no-fallback]"
            )
        objective, target = argv[0], argv[1]
        capabilities = [item.strip() for item in _flag(argv, "--capabilities", "").split(",") if item.strip()]
        parameters = _json_flag(argv, "--parameters")
        mission_id = _flag(argv, "--mission")
        timeout = float(_flag(argv, "--timeout", "0") or 0)
        allow_fallback = "--no-fallback" not in argv
        print(
            app.renderer.render(
                _service().execute_chain(
                    objective,
                    capabilities,
                    target,
                    parameters=parameters,
                    mission_id=mission_id,
                    timeout=timeout,
                    allow_fallback=allow_fallback,
                ),
                fmt="json",
            )
        )
        return 0

    def _tools_contract(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools contract <tool_id>")
        print(app.renderer.render(_service().contract(argv[0]), fmt="json"))
        return 0

    def _tools_contracts(_argv: list[str]) -> int:
        print(app.renderer.render(_service().contracts(), fmt="json"))
        return 0

    def _tools_recommend(argv: list[str]) -> int:
        if not argv:
            raise SystemExit("usage: hunterx tools recommend <capability_id>")
        print(app.renderer.render(_service().recommend(argv[0]), fmt="json"))
        return 0

    app.registry.register("tools list", _tools_list, help_text="List registered tools")
    app.registry.register("tools show", _tools_show, help_text="Show a tool knowledge contract")
    app.registry.register("tools contract", _tools_contract, help_text="Show a tool's consolidated machine-readable contract")
    app.registry.register("tools contracts", _tools_contracts, help_text="List consolidated contracts for every tool")
    app.registry.register("tools capabilities", _tools_capabilities, help_text="Show tool capabilities or the capability catalog")
    app.registry.register("tools health", _tools_health, help_text="Show tool health")
    app.registry.register("tools versions", _tools_versions, help_text="Show tool versions")
    app.registry.register("tools execute", _tools_execute, help_text="Execute a tool against a target (structured)")
    app.registry.register("tools inspect-result", _tools_inspect_result, help_text="Inspect a stored execution result")
    app.registry.register("tools parse", _tools_parse, help_text="Parse saved tool output offline")
    app.registry.register("tools normalize", _tools_normalize, help_text="Normalize parsed records offline")
    app.registry.register("tools chain", _tools_chain, help_text="Plan a dependency-aware tool chain")
    app.registry.register("tools chain-execute", _tools_chain_execute, help_text="Plan and execute an end-to-end tool chain")
    app.registry.register("tools recommend", _tools_recommend, help_text="Recommend tools for a capability")
