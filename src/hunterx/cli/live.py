# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live mission console and run-artifact recording.

The human-facing half of the mission execution loop. It listens to the real
mission lifecycle events published on the platform event bus and renders them
as live progress, and it records every event so a finished mission leaves
three artifacts behind:

- ``events.jsonl`` — one JSON line per lifecycle event (streamed live);
- ``results.json`` — the final mission JSON (the established CLI contract)
  plus run metadata and artifact paths;
- ``report.txt`` — a lightweight human-readable mission report.

Nothing here invents progress: every line maps to a real lifecycle event
produced by the mission runner or the orchestration service. Secret-bearing
command lines are redacted before they ever reach the bus (see
:func:`redact_command`), so neither the renderer nor the artifacts can leak
credentials.
"""

from __future__ import annotations

import contextlib
import json
import re
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from hunterx.config.paths import hunterx_root
from hunterx.domain.events import DomainEvent
from hunterx.reporting.mission_report import build_mission_text_report
from hunterx.shared.masking import mask_value
from hunterx.shared.time import utcnow_iso
from hunterx.tools.recon.runner import (
    CommandObservation,
    register_command_observer,
    unregister_command_observer,
)

#: Option names whose value is a secret and must never be rendered verbatim.
_SECRET_OPTIONS = frozenset(
    {
        "token",
        "api-key",
        "apikey",
        "api_key",
        "key",
        "secret",
        "client-secret",
        "password",
        "pass",
        "passwd",
        "auth",
        "authorization",
        "proxy-auth",
        "proxy-authorization",
        "cookie",
        "session",
        "session-token",
        "bearer",
        "access-token",
        "refresh-token",
        "webhook",
        "signature",
        "private-key",
        "ssh-key",
        "secret-key",
    }
)

#: Header-style values (``Authorization: Bearer ...``) whose body is a secret.
_HEADER_SECRET_RE = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|api-key|x-api-key)\s*:\s*(.*)$",
    re.IGNORECASE,
)

#: JWT / signed-token shape: ``header.payload.signature``.
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

#: URL embedded credentials: ``scheme://user:pass@host``.
_URL_CREDENTIALS_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<credentials>[^/@\s]+@)(?P<rest>.*)$", re.IGNORECASE)

_CREDENTIALS_IN_URL_RE = re.compile(r"(?P<scheme>://)(?P<user>[^/@:\s]+):(?P<password>[^/@\s]+)@")


def redact_command(argv: Sequence[str]) -> str:
    """Join ``argv`` into a displayable command with secrets masked.

    Redaction rules (applied before anything is published or persisted):

    - values of known secret options (``--token X``, ``--api-key=Y``) are
      masked;
    - ``Authorization:``/``Cookie:`` style header values are masked;
    - URLs with embedded credentials have the credentials masked;
    - JWT-shaped tokens are fully masked.

    The rest of the command line is the actual argv that ran — never a
    reconstruction.
    """
    parts = [str(part) for part in argv]
    mask_next = [False] * len(parts)
    for index, part in enumerate(parts):
        if _is_secret_option(part):
            if "=" in part:
                name, value = part.split("=", 1)
                parts[index] = f"{name}={mask_value(value)}"
            elif index + 1 < len(parts):
                mask_next[index + 1] = True
    for index, part in enumerate(parts):
        if mask_next[index]:
            parts[index] = mask_value(part)
            continue
        match = _HEADER_SECRET_RE.match(part)
        if match:
            parts[index] = f"{match.group(1)}: {mask_value(match.group(2))}"
            continue
        url_match = _URL_CREDENTIALS_RE.match(part)
        if url_match:
            parts[index] = (
                f"{url_match.group('scheme')}{mask_value(url_match.group('credentials'))}"
                f"{url_match.group('rest')}"
            )
            continue
        if _JWT_RE.match(part) or _CREDENTIALS_IN_URL_RE.search(part):
            parts[index] = mask_value(part)
    return " ".join(parts)


def _is_secret_option(part: str) -> bool:
    """Return ``True`` when ``part`` is a secret-bearing option token."""
    name = part.lstrip("-").split("=", 1)[0].lower()
    return name in _SECRET_OPTIONS


#: Outcome → human description for ``mission.tool.completed``.
_TOOL_OUTCOMES: dict[str, str] = {
    "evidence": "evidence captured",
    "negative": "explicit empty result (TESTED, no findings)",
    "uninformative": "empty result (no evidence; NOT_ASSESSED)",
}


class LiveMissionRenderer:
    """Render a mission's live lifecycle events as human progress.

    Args:
        bus: the platform event bus to subscribe to.
        mission_id: only events for this mission are rendered.
        viewer: optional callable ``mission_id -> OrchestratedMission`` used
            to enrich sparse events (observation types, hypothesis statements,
            decision reasons) with live mission state.
        stream: output stream (defaults to ``sys.stderr`` so the established
            stdout JSON contract is never polluted).
        width: maximum line width for truncation.

    """

    def __init__(
        self,
        bus: Any,
        *,
        mission_id: str,
        viewer: Callable[[str], Any] | None = None,
        stream: Any | None = None,
        width: int = 100,
    ) -> None:
        self._bus = bus
        self._mission_id = mission_id
        self._viewer = viewer or (lambda _mission_id: None)
        self._stream = stream if stream is not None else sys.stderr
        self._width = int(width)
        self._closed = False
        self._seen_cells: set[str] = set()
        bus.subscribe("mission.*", self._on_event)
        bus.subscribe("tool.command", self._on_event)
        bus.subscribe("coverage.updated", self._on_event)
        self._render_mission_header()

    def _render_mission_header(self) -> None:
        """Render the mission header line from the live mission aggregate.

        The ``mission.started`` event is published by mission creation, which
        precedes this renderer's subscription; the header is instead read from
        the real mission state (policy, target, strategy) so the operator sees
        the same facts the event carried — never invented progress.
        """
        mission = self._mission()
        if mission is None:
            return
        try:
            payload = {
                "objective": mission.policy.objective_name,
                "target": mission.context.target_id,
                "strategy": mission.policy.strategy.value,
            }
        except Exception:  # noqa: BLE001 - the header is best-effort
            return
        line = self._render_mission_started(payload)
        if line:
            self._write(line)

    # -- event handling -----------------------------------------------------

    def _on_event(self, event: DomainEvent) -> None:
        if self._closed:
            return
        payload = dict(event.payload or {})
        mission_id = str(payload.get("mission_id") or event.mission_id or "")
        if mission_id != self._mission_id:
            return
        handler = _EVENT_HANDLERS.get(event.event_type)
        if handler is None:
            return
        try:
            line = handler(self, payload)
        except Exception:  # noqa: BLE001 - rendering must never break the mission
            return
        if line:
            self._write(line)

    def summary(self, overview: dict[str, Any]) -> None:
        """Render the compact human completion summary."""
        counts = overview.get("counts") or {}
        lines = [
            "",
            "==================================================",
            f"  {str(overview.get('status', '')).upper():<10} {overview.get('mission_id', '')}",
            "==================================================",
            f"  target           {overview.get('target_id', '')}",
            f"  planning state   {overview.get('planning_state', '')}",
            f"  phase            {overview.get('current_phase', '')}",
            f"  coverage         {overview.get('coverage_ratio', 0.0):.0%}",
            f"  assets           {counts.get('assets', 0)}",
            f"  technologies     {counts.get('technologies', 0)}",
            f"  services         {counts.get('services', 0)}",
            f"  endpoints        {counts.get('endpoints', 0)}",
            f"  observations     {counts.get('observations', 0)}",
            f"  hypotheses       {counts.get('hypotheses', 0)}",
            f"  findings         {counts.get('findings', 0)}",
            f"  decisions        {counts.get('decisions', 0)}",
            f"  tool executions  {counts.get('tool_executions', 0)}",
            f"  negative evidence {counts.get('negative_evidence', 0)}",
        ]
        artifacts = overview.get("artifacts")
        if isinstance(artifacts, dict) and artifacts:
            lines.append("")
            lines.append("  artifacts")
            for kind in ("report", "results", "events"):
                path = artifacts.get(kind)
                if path:
                    lines.append(f"    {kind:<8} {path}")
        if overview.get("reason"):
            lines.append("")
            lines.append(f"  reason           {overview['reason']}")
        lines.append("")
        self._write("\n".join(lines))

    def close(self) -> None:
        """Unsubscribe from the bus (safe to call more than once)."""
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):  # teardown is best-effort
            self._bus.unsubscribe("mission.*", self._on_event)
        with contextlib.suppress(Exception):  # teardown is best-effort
            self._bus.unsubscribe("tool.command", self._on_event)
        with contextlib.suppress(Exception):  # teardown is best-effort
            self._bus.unsubscribe("coverage.updated", self._on_event)

    # -- renderers ----------------------------------------------------------

    def _render_mission_started(self, payload: dict[str, Any]) -> str:
        return (
            f"[HUNT] mission {self._mission_id} started"
            f" · objective {payload.get('objective', '')}"
            f" · target {payload.get('target', '')}"
            f" · strategy {payload.get('strategy', '')}"
        )

    def _render_preflight(self, payload: dict[str, Any]) -> str:
        status = payload.get("status", "")
        reason = payload.get("reason", "")
        line = f"[PREFLIGHT] {status}"
        if reason:
            line += f" — {self._truncate(reason)}"
        return line

    def _render_phase_started(self, payload: dict[str, Any]) -> str:
        phase = str(payload.get("phase") or payload.get("phase_kind") or "").upper()
        if not phase:
            return ""
        return f"\n── {phase} ──"

    def _render_action_selected(self, payload: dict[str, Any]) -> str:
        decision = self._latest_decision()
        capability = decision.get("capability") if decision else payload.get("capability", "")
        tool_id = decision.get("tool_id") if decision else payload.get("tool_id", "")
        label = f">> decide {capability}" if capability else ">> decide"
        if tool_id:
            label += f" with {tool_id}"
        if decision and decision.get("ai_assisted"):
            label += " [AI-assisted]"
        return label

    def _render_tool_started(self, payload: dict[str, Any]) -> str:
        tool_id = payload.get("tool_id", "")
        capability = payload.get("capability", "")
        target = payload.get("target", "")
        label = f">> run {tool_id}"
        if capability:
            label += f" ({capability})"
        if target:
            label += f" -> {target}"
        return label

    def _render_tool_command(self, payload: dict[str, Any]) -> str:
        command = payload.get("command", "")
        if not command:
            return ""
        return f"     $ {self._truncate(command)}"

    def _render_tool_completed(self, payload: dict[str, Any]) -> str:
        tool_id = payload.get("tool_id", "")
        outcome = payload.get("outcome", "")
        label = _TOOL_OUTCOMES.get(str(outcome), outcome)
        duration = payload.get("duration_ms")
        if duration:
            label += f" ({int(duration)} ms)"
        return f"   ok {tool_id} — {label}"

    def _render_tool_failed(self, payload: dict[str, Any]) -> str:
        tool_id = payload.get("tool_id", "")
        error = payload.get("error", "")
        label = f"  FAIL {tool_id}"
        if error:
            label += f" — {self._truncate(str(error))}"
        return label

    def _render_observation(self, payload: dict[str, Any]) -> str:
        observation = self._observation(payload.get("observation_id", ""))
        if observation is None:
            return ""
        tool_id = payload.get("tool_id") or observation.get("tool_id", "")
        kind = observation.get("observation_type", "")
        label = f"   observation: {kind}"
        if tool_id:
            label += f" from {tool_id}"
        return label

    def _render_hypothesis(self, payload: dict[str, Any]) -> str:
        hypothesis = self._hypothesis(payload.get("hypothesis_id", ""))
        if hypothesis is None:
            return ""
        statement = hypothesis.get("statement", "")
        state = payload.get("state") or hypothesis.get("state", "")
        label = "   hypothesis"
        if state:
            label += f" [{state}]"
        if statement:
            label += f": {self._truncate(str(statement))}"
        return label

    def _render_finding(self, payload: dict[str, Any]) -> str:
        finding = self._finding(payload.get("finding_id", ""))
        if finding is None:
            return ""
        vulnerability_class = finding.get("vulnerability_class", "")
        severity = finding.get("severity", "")
        asset = finding.get("asset_key") or finding.get("target") or ""
        label = f"   finding: {vulnerability_class}"
        if severity:
            label += f" [{severity}]"
        if asset:
            label += f" on {asset}"
        return label

    def _render_coverage(self, payload: dict[str, Any]) -> str:
        capability = payload.get("capability", "")
        state = payload.get("state", "")
        tool_id = payload.get("tool_id", "")
        notes = payload.get("notes", "")
        key = f"{payload.get('asset_key', '')}:{capability}"
        if key in self._seen_cells:
            return ""
        self._seen_cells.add(key)
        label = f"   coverage: {capability} = {state}"
        if tool_id and state == "tested":
            label += f" (via {tool_id})"
        if notes:
            label += f" — {self._truncate(str(notes))}"
        return label

    def _render_blocked(self, payload: dict[str, Any]) -> str:
        reason = payload.get("reason", "")
        label = "[BLOCKED] mission blocked by tool readiness gate"
        if reason:
            label += f" — {self._truncate(str(reason))}"
        return label

    def _render_completed(self, _payload: dict[str, Any]) -> str:
        return "[DONE] mission completed"

    # -- enrichment helpers -------------------------------------------------

    def _mission(self) -> Any:
        try:
            return self._viewer(self._mission_id)
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            return None

    def _latest_decision(self) -> dict[str, Any]:
        mission = self._mission()
        if mission is None:
            return {}
        decisions = getattr(mission, "decisions", ())
        if not decisions:
            return {}
        try:
            return decisions[-1].to_dict()
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            return {}

    def _observation(self, observation_id: str) -> dict[str, Any] | None:
        mission = self._mission()
        if mission is None:
            return None
        try:
            observation = mission.observation(observation_id)
            return observation.to_dict() if observation is not None else None
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            return None

    def _hypothesis(self, hypothesis_id: str) -> dict[str, Any] | None:
        mission = self._mission()
        if mission is None:
            return None
        try:
            hypothesis = mission.hypothesis(hypothesis_id)
            return hypothesis.to_dict() if hypothesis is not None else None
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            return None

    def _finding(self, finding_id: str) -> dict[str, Any] | None:
        mission = self._mission()
        if mission is None:
            return None
        try:
            for finding in mission.context.findings:
                if str(finding.get("finding_id", "")) == finding_id:
                    return finding
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            pass
        return None

    # -- output -------------------------------------------------------------

    def _write(self, text: str) -> None:
        try:
            self._stream.write(text + "\n")
            self._stream.flush()
        except Exception:  # noqa: BLE001 - output must never break the mission
            pass

    def _truncate(self, text: str) -> str:
        text = " ".join(str(text).split())
        if len(text) <= self._width:
            return text
        return text[: self._width - 3] + "..."


_EVENT_HANDLERS: dict[str, Callable[[LiveMissionRenderer, dict[str, Any]], str]] = {
    "mission.started": LiveMissionRenderer._render_mission_started,
    "mission.preflight.completed": LiveMissionRenderer._render_preflight,
    "mission.phase.started": LiveMissionRenderer._render_phase_started,
    "mission.action.selected": LiveMissionRenderer._render_action_selected,
    "mission.tool.started": LiveMissionRenderer._render_tool_started,
    "tool.command": LiveMissionRenderer._render_tool_command,
    "mission.tool.completed": LiveMissionRenderer._render_tool_completed,
    "mission.tool.failed": LiveMissionRenderer._render_tool_failed,
    "mission.observation.created": LiveMissionRenderer._render_observation,
    "mission.hypothesis.created": LiveMissionRenderer._render_hypothesis,
    "mission.hypothesis.updated": LiveMissionRenderer._render_hypothesis,
    "mission.finding.created": LiveMissionRenderer._render_finding,
    "coverage.updated": LiveMissionRenderer._render_coverage,
    "mission.completed": LiveMissionRenderer._render_completed,
    "mission.blocked": LiveMissionRenderer._render_blocked,
}


class MissionRunRecorder:
    """Collect a mission's lifecycle events and write run artifacts.

    The recorder subscribes to the same canonical events the renderer shows
    and mirrors them to ``events.jsonl`` as they occur. When the run finishes
    (:meth:`finish`) it writes ``results.json`` (the final mission JSON plus
    run metadata) and ``report.txt`` (the human-readable mission report).

    Args:
        bus: the platform event bus.
        mission_id: only events for this mission are recorded.
        output_dir: artifact directory (defaults to
            ``<project root>/artifacts/hunterx-results/<mission_id>``).

    """

    def __init__(self, bus: Any, *, mission_id: str, output_dir: str | Path | None = None) -> None:
        self._bus = bus
        self._mission_id = mission_id
        self._output_dir = Path(output_dir) if output_dir else hunterx_root() / "artifacts" / "hunterx-results" / mission_id
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._events_path = self._output_dir / "events.jsonl"
        self._results_path = self._output_dir / "results.json"
        self._report_path = self._output_dir / "report.txt"
        self._events: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._started_at = utcnow_iso()
        self._started_epoch = time.time()
        self._finished = False
        bus.subscribe("mission.*", self._on_event)
        bus.subscribe("tool.command", self._on_event)
        bus.subscribe("coverage.updated", self._on_event)
        register_command_observer(self._publish_command)

    # -- event capture ------------------------------------------------------

    def _on_event(self, event: DomainEvent) -> None:
        try:
            mission_id = str((event.payload or {}).get("mission_id") or event.mission_id or "")
            if mission_id != self._mission_id:
                return
            record = {
                "event_type": event.event_type,
                "occurred_at": event.occurred_at,
                "payload": event.payload,
            }
            with self._lock:
                self._events.append(record)
                self._append_jsonl(record)
        except Exception:  # noqa: BLE001 - recording must never break the mission
            pass

    def _publish_command(self, observation: CommandObservation) -> None:
        """Publish a redacted command observation onto the bus.

        Redaction happens here, before the event is published, so neither the
        event store, the renderer nor the artifacts ever carry raw secrets.
        """
        if observation.mission_id != self._mission_id:
            return
        with contextlib.suppress(Exception):  # command visibility must never break a tool
            self._bus.publish(
                DomainEvent(
                    event_type="tool.command",
                    payload={
                        "mission_id": observation.mission_id,
                        "tool_id": observation.tool_id,
                        "execution_id": observation.execution_id,
                        "capability": observation.capability,
                        "action_id": observation.action_id,
                        "target": observation.target,
                        "command": redact_command(observation.argv),
                    },
                    source="tool.recon.runner",
                    mission_id=observation.mission_id,
                    execution_id=observation.execution_id or None,
                )
            )

    # -- artifacts ----------------------------------------------------------

    def finish(
        self,
        overview: dict[str, Any],
        *,
        status: str = "completed",
        error: str = "",
        mission: Any = None,
    ) -> dict[str, Any]:
        """Write the run artifacts (idempotent) and return their paths."""
        with self._lock:
            if self._finished:
                return self.artifact_paths()
            self._finished = True
        unregister_command_observer(self._publish_command)
        report_text = build_mission_text_report(
            self._mission_id,
            overview,
            list(self._events),
            mission=mission,
            status=status,
            error=error,
        )
        self._report_path.write_text(report_text, encoding="utf-8")
        results = {
            **overview,
            "status": status,
            "error": error,
            "mission_id": self._mission_id,
            "started_at": self._started_at,
            "finished_at": utcnow_iso(),
            "duration_seconds": round(time.time() - self._started_epoch, 2),
            "event_count": len(self._events),
            "artifact_paths": self.artifact_paths(),
        }
        self._results_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        return self.artifact_paths()

    def artifact_paths(self) -> dict[str, str]:
        """Return the artifact file paths."""
        return {
            "report": str(self._report_path),
            "results": str(self._results_path),
            "events": str(self._events_path),
        }

    def events(self) -> list[dict[str, Any]]:
        """Return the recorded events (JSON-safe)."""
        with self._lock:
            return list(self._events)

    def close(self) -> None:
        """Release the command observer (idempotent)."""
        unregister_command_observer(self._publish_command)

    def _append_jsonl(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, default=str)
        with self._events_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()


__all__ = [
    "LiveMissionRenderer",
    "MissionRunRecorder",
    "redact_command",
]
