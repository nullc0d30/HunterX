# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Lightweight human-readable mission report builder.

``build_mission_text_report`` assembles the ``report.txt`` artifact of a
``hunterx hunt`` run from the final mission overview (the established JSON
contract) plus the recorded lifecycle events. Like the live renderer, it
never fabricates facts: every line maps to real mission state, and entries
whose data is absent are simply omitted.

The builder is intentionally defensive — a reporting artifact must never
crash a finished mission — so every lookup is best-effort and JSON-safe.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.mission_orchestration.models import CoverageCell

#: Max number of rows rendered per list section.
_MAX_ROWS = 200

#: Short fields shown for generic context entries (assets/technologies/...).
_ENTRY_FIELDS = (
    "name",
    "title",
    "host",
    "port",
    "service",
    "product",
    "vendor",
    "version",
    "url",
    "path",
    "method",
    "identity",
    "content_type",
)

_FINDING_FIELDS = (
    "title",
    "severity",
    "tool",
    "confidence",
    "stage",
    "asset_key",
    "target",
    "description",
)

_PATH_FIELDS = ("title", "description", "asset", "asset_key", "target", "hops", "path")


def build_mission_text_report(
    mission_id: str,
    overview: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    mission: Any = None,
    status: str = "completed",
    error: str = "",
) -> str:
    """Build the human-readable mission report text.

    Args:
        mission_id: the mission identifier.
        overview: the final mission overview mapping (mission JSON contract).
        events: recorded lifecycle events (``event_type``/``occurred_at``/
            ``payload`` records).
        mission: optional :class:`OrchestratedMission` for enriched sections
            (attack surface, hypotheses, findings, coverage, decisions).
        status: run status (``completed``/``interrupted``/...).
        error: final error message, if any.

    Returns:
        The report text (never empty).

    """
    counts = _mapping(overview.get("counts"))
    started_at = _first_event_time(events)
    finished_at = _last_event_time(events)
    tool_stats = _tool_stats(events)

    lines: list[str] = []
    _add_heading(lines, "HUNTERX MISSION REPORT")
    lines += [
        f"Mission ID        {mission_id}",
        f"Status            {status}",
        f"Target            {_scalar(overview.get('target_id'))}",
        f"Objective         {_scalar(overview.get('objective'))}",
        f"Strategy          {_scalar(overview.get('strategy'))}",
        f"Planning state    {_scalar(overview.get('planning_state'))}",
        f"Phase             {_scalar(overview.get('current_phase'))}",
        f"Coverage ratio    {_percent(overview.get('coverage_ratio'))}",
        f"Started at        {started_at}",
        f"Finished at       {finished_at}",
    ]
    if error:
        lines.append(f"Error             {_truncate(error, 200)}")

    _add_heading(lines, "EXECUTIVE SUMMARY")
    summary_rows = [
        ("Assets", "assets"),
        ("Technologies", "technologies"),
        ("Services", "services"),
        ("Endpoints", "endpoints"),
        ("Parameters", "parameters"),
        ("Observations", "observations"),
        ("Hypotheses", "hypotheses"),
        ("Open hypotheses", "open_hypotheses"),
        ("Decisions", "decisions"),
        ("Tool executions", "tool_executions"),
        ("Findings", "findings"),
        ("Validated findings", "validated_findings"),
        ("Report-ready findings", "report_ready_findings"),
        ("Negative evidence", "negative_evidence"),
        ("Evidence records", "evidence"),
        ("Proofs", "proofs"),
        ("Attack paths", "attack_paths"),
    ]
    for label, key in summary_rows:
        if key in counts:
            lines.append(f"  {label:<22} {_scalar(counts[key])}")
    outcome = _mapping(overview.get("outcome"))
    if outcome:
        lines.append("  Outcome:")
        for label, key in (
            ("Objectives complete", "objectives_complete"),
            ("Findings validated", "findings_validated"),
            ("Findings report ready", "findings_report_ready"),
            ("Hypotheses resolved", "hypotheses_resolved"),
            ("Attack paths discovered", "attack_paths_discovered"),
            ("Executions used", "executions_used"),
            ("Stop condition", "stop_condition"),
        ):
            if key in outcome:
                lines.append(f"    {label:<24} {_scalar(outcome[key])}")

    _add_heading(lines, "SCOPE")
    scope = _mapping(overview.get("scope"))
    if not scope and mission is not None:
        scope = _mapping(_call(mission, "context", "scope", "to_dict"))
    for label, key in (
        ("Included targets", "included_targets"),
        ("Excluded assets", "excluded_assets"),
        ("Included domains", "included_domains"),
        ("Authorization", "authorization_contexts"),
    ):
        value = scope.get(key)
        if value:
            lines.append(f"  {label:<18} {_list_text(value)}")

    budget = _mapping(overview.get("budget"))
    if budget:
        _add_heading(lines, "RESOURCE BUDGET")
        for label, key in (
            ("Executions", "executions_used"),
            ("Executions budget", "executions_budget"),
            ("Time used (s)", "time_used_seconds"),
            ("Time budget (s)", "time_budget_seconds"),
            ("Max concurrency", "max_concurrency"),
        ):
            if key in budget:
                lines.append(f"  {label:<18} {_scalar(budget[key])}")

    _add_heading(lines, "RECONNAISSANCE (OBSERVATIONS)")
    observations = _mission_observations(mission)
    if observations:
        for observation in observations[: _MAX_ROWS]:
            content = _content_summary(observation.get("content"))
            lines.append(
                f"  - [{_scalar(observation.get('observation_type'))}] "
                f"{_scalar(observation.get('tool_id'))} on {_scalar(observation.get('asset_key'))}"
                f"{(' — ' + content) if content else ''}"
            )
    else:
        lines.append("  (no observations recorded)")

    _add_heading(lines, "TARGET MODEL")
    for label, entries in (
        ("Assets", _context_entries(mission, "assets")),
        ("Technologies", _context_entries(mission, "technologies")),
        ("Services", _context_entries(mission, "services")),
        ("Endpoints", _context_entries(mission, "endpoints")),
        ("Parameters", _context_entries(mission, "parameters")),
    ):
        if entries:
            lines.append(f"  {label}:")
            for key, entry in entries[: _MAX_ROWS]:
                lines.append(f"    - {_entry_text(key, entry)}")

    _add_heading(lines, "HYPOTHESES")
    hypotheses = _mission_hypotheses(mission)
    if hypotheses:
        for hypothesis in hypotheses[: _MAX_ROWS]:
            lines.append(
                f"  - [{_scalar(hypothesis.get('state'))}] "
                f"{_scalar(hypothesis.get('category'))}: {_truncate(_scalar(hypothesis.get('statement')), 160)}"
                f" (confidence {_scalar(hypothesis.get('confidence'))}, priority {_scalar(hypothesis.get('priority'))})"
            )
    else:
        lines.append("  (no hypotheses recorded)")

    _add_heading(lines, "ATTACK PATHS")
    attack_paths = _context_entries(mission, "attack_paths")
    if attack_paths:
        for key, entry in attack_paths[: _MAX_ROWS]:
            lines.append(f"  - {_entry_text(key, entry)}")
    else:
        lines.append("  (none recorded)")

    _add_heading(lines, "FINDINGS")
    findings = _mission_findings(mission)
    if findings:
        for finding in findings[: _MAX_ROWS]:
            parts = []
            for field in _FINDING_FIELDS:
                value = finding.get(field)
                if value not in (None, "", []):
                    parts.append(f"{field}={value}")
            lines.append(f"  - {_scalar(finding.get('vulnerability_class'))} {' '.join(parts)}")
    else:
        lines.append("  (none recorded)")

    _add_heading(lines, "NEGATIVE EVIDENCE")
    negative = _mission_negative(mission)
    if negative:
        for record in negative[: _MAX_ROWS]:
            lines.append(
                f"  - {_scalar(record.get('capability'))} on {_scalar(record.get('asset_key'))} "
                f"(tool {_scalar(record.get('tool_id'))}, outcome {_scalar(record.get('outcome'))})"
            )
    else:
        lines.append("  (none recorded)")
    lines.append("  Note: negative evidence records what was tested and not found; the")
    lines.append("  absence of findings never proves the absence of a vulnerability.")

    _add_heading(lines, "TOOL EXECUTION SUMMARY")
    executions = _mission_tool_executions(mission)
    if executions:
        for execution in executions[: _MAX_ROWS]:
            lines.append(
                f"  - {_scalar(execution.get('tool_id'))} ({_scalar(execution.get('capability'))}) "
                f"-> {_scalar(execution.get('asset_key'))} at {_scalar(execution.get('executed_at'))}"
            )
    if tool_stats:
        lines.append("  Live event counts:")
        lines.append(
            f"    started {tool_stats['started']} · completed {tool_stats['completed']} "
            f"· failed {tool_stats['failed']} · commands seen {tool_stats['commands']}"
        )

    _add_heading(lines, "AI / DECISION SUMMARY")
    decisions = _mission_decisions(mission)
    if decisions:
        ai_assisted = sum(1 for decision in decisions if decision.get("ai_assisted"))
        lines.append(f"  Total decisions {len(decisions)} (AI-assisted {ai_assisted})")
        for decision in decisions[: _MAX_ROWS]:
            marker = " [AI-assisted]" if decision.get("ai_assisted") else ""
            lines.append(
                f"  - {_scalar(decision.get('capability'))} with {_scalar(decision.get('tool_id'))}"
                f"{marker}: {_truncate(_scalar(decision.get('reason')), 160)}"
            )
    else:
        lines.append("  (no decisions recorded)")

    _add_heading(lines, "COVERAGE")
    cells = _mission_coverage_cells(mission)
    if cells:
        for cell in cells[: _MAX_ROWS]:
            lines.append(
                f"  - {_scalar(cell.get('asset_key'))} | {_scalar(cell.get('capability'))} "
                f"= {_scalar(cell.get('state')).upper()}"
                f"{(' via ' + _scalar(cell.get('tool_id'))) if cell.get('tool_id') else ''}"
                f"{(' — ' + _truncate(_scalar(cell.get('notes')), 120)) if cell.get('notes') else ''}"
            )
    else:
        lines.append("  (no coverage cells recorded)")

    _add_heading(lines, "LIMITATIONS")
    limitations = []
    if status != "completed":
        limitations.append(f"The run ended with status '{status}' (error: {error or 'none'}).")
    scope_text = scope.get("included_targets") or scope.get("included_domains")
    if not scope_text:
        limitations.append("The authorized scope of this run is not recorded.")
    limitations.append(
        "Findings are evidence-backed observations; uninformative tool results were "
        "recorded as NOT_ASSESSED rather than as assessments."
    )
    limitations.append(
        "Coverage reflects what was actually tested with real tool executions; "
        "untested cells remain NOT_ASSESSED."
    )
    for limitation in limitations:
        lines.append(f"  - {limitation}")

    _add_heading(lines, "FINAL ASSESSMENT")
    if outcome:
        lines.append(
            f"  Objectives complete: {_scalar(outcome.get('objectives_complete'))} · "
            f"validated findings: {_scalar(outcome.get('findings_validated'))} · "
            f"coverage: {_percent(outcome.get('coverage_ratio'))} · "
            f"stop condition: {_scalar(outcome.get('stop_condition'))}"
        )
    else:
        lines.append(f"  Mission {mission_id} finished with status '{status}'.")
    lines.append("")
    lines.append("Report generated from the mission's recorded lifecycle events.")
    return "\n".join(lines) + "\n"


# -- section helpers ---------------------------------------------------------


def _add_heading(lines: list[str], title: str) -> None:
    if lines and not lines[-1].startswith("="):
        lines.append("")
    lines.append("=" * 66)
    lines.append(f"  {title}")
    lines.append("=" * 66)


def _tool_stats(events: list[dict[str, Any]]) -> dict[str, int]:
    started = completed = failed = commands = 0
    for event in events:
        event_type = str(event.get("event_type") or "")
        if event_type == "mission.tool.started":
            started += 1
        elif event_type == "mission.tool.completed":
            completed += 1
        elif event_type == "mission.tool.failed":
            failed += 1
        elif event_type == "tool.command":
            commands += 1
    return {"started": started, "completed": completed, "failed": failed, "commands": commands}


def _first_event_time(events: list[dict[str, Any]]) -> str:
    for event in events:
        value = event.get("occurred_at")
        if value:
            return _scalar(value)
    return ""


def _last_event_time(events: list[dict[str, Any]]) -> str:
    for event in reversed(events):
        value = event.get("occurred_at")
        if value:
            return _scalar(value)
    return ""


def _mission_observations(mission: Any) -> list[dict[str, Any]]:
    return _to_dict_list(_attr(mission, "observations"))


def _mission_hypotheses(mission: Any) -> list[dict[str, Any]]:
    return _to_dict_list(_attr(mission, "hypotheses"))


def _mission_decisions(mission: Any) -> list[dict[str, Any]]:
    return _to_dict_list(_attr(mission, "decisions"))


def _mission_negative(mission: Any) -> list[dict[str, Any]]:
    return _to_dict_list(_attr(mission, "negative_evidence"))


def _mission_findings(mission: Any) -> list[dict[str, Any]]:
    context = _attr(mission, "context")
    findings = _attr(context, "findings")
    if not isinstance(findings, (list, tuple)):
        return []
    return [finding for finding in findings if isinstance(finding, dict)]


def _mission_tool_executions(mission: Any) -> list[dict[str, Any]]:
    context = _attr(mission, "context")
    executions = _attr(context, "tool_executions")
    if not isinstance(executions, (list, tuple)):
        return []
    return [execution for execution in executions if isinstance(execution, dict)]


def _mission_coverage_cells(mission: Any) -> list[dict[str, Any]]:
    try:
        cells = mission.coverage_cells()
    except Exception:  # noqa: BLE001 - reporting is best-effort
        return []
    result: list[dict[str, Any]] = []
    for cell in cells:
        if isinstance(cell, CoverageCell):
            result.append(cell.to_dict())
        elif isinstance(cell, dict):
            result.append(cell)
    return result


def _context_entries(mission: Any, name: str) -> list[tuple[str, dict[str, Any]]]:
    context = _attr(mission, "context")
    entries = _attr(context, name)
    if not isinstance(entries, dict):
        return []
    return [(str(key), value) for key, value in entries.items() if isinstance(value, dict)]


def _entry_text(key: str, entry: dict[str, Any]) -> str:
    parts: list[str] = []
    for field in _ENTRY_FIELDS:
        value = entry.get(field)
        if value not in (None, "", [], {}):
            parts.append(f"{field}={value}")
    content = entry.get("content")
    if content not in (None, "", {}):
        summary = _content_summary(content)
        if summary:
            parts.append(f"content={_truncate(summary, 120)}")
    return f"{key} {' '.join(parts)}".strip()


def _content_summary(content: Any) -> str:
    if content in (None, "", {}):
        return ""
    if isinstance(content, dict):
        parts = []
        for key, value in list(content.items())[:5]:
            if value not in (None, "", [], {}):
                parts.append(f"{key}={value}")
        return _truncate(", ".join(parts), 200) if parts else ""
    if isinstance(content, (list, tuple)):
        return _truncate(", ".join(str(item) for item in content[:5]), 200)
    return _truncate(str(content), 200)


# -- primitive helpers -------------------------------------------------------


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def _percent(value: Any) -> str:
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return _scalar(value)


def _list_text(value: Any) -> str:
    if not isinstance(value, (list, tuple)):
        return _scalar(value)
    return ", ".join(str(item) for item in value) or "—"


def _truncate(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def _attr(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    try:
        return getattr(obj, name, None)
    except Exception:  # noqa: BLE001 - reporting is best-effort
        return None


def _call(obj: Any, *path: str) -> Any:
    current = obj
    for step in path:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(step)
            continue
        try:
            current = getattr(current, step)
        except Exception:  # noqa: BLE001 - reporting is best-effort
            return None
        if callable(current):
            try:
                current = current()
            except Exception:  # noqa: BLE001 - reporting is best-effort
                return None
    return current


def _to_dict_list(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, (list, tuple)):
        return []
    result: list[dict[str, Any]] = []
    for item in items:
        try:
            if isinstance(item, dict):
                result.append(item)
            elif hasattr(item, "to_dict"):
                result.append(item.to_dict())
        except Exception:  # noqa: BLE001 - reporting is best-effort
            continue
    return result


__all__ = ["build_mission_text_report"]
