# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability execution engine.

Lifts the proven probe path out of the validation harness into the application
layer: drains the attack-surface assessment queue and for every ready
``(surface, capability, context)`` task:

    1. checks capability applicability from target evidence (never assumed),
    2. attempts the capability's tool chain (scanner -> scanner -> native
       HunterX strategy), recording every tool execution honestly
       (tool / command / exit code / stdout status / parsed result / duration),
    3. executes the native differential probes — multi-vector, one probe per
       signal strategy — bounded and loopback-guarded,
    4. analyzes every probe, settles the task + assignment with the verdict,
    5. records the per-(capability x surface x context) outcome and, when a
       session exists, repeats the execution in the authenticated context
       (auth-context matrix),
    6. aggregates exactly-one authoritative status per capability and persists
       the mission's ``capability_coverage.json``.

Blocking is blocking, failure is failure: a probe refused on a non-loopback
target is BLOCKED, an execution error is FAILED, an absent tool is recorded
``unavailable`` and the chain falls through — a capability is never silently
marked complete.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import replace as _replace
from typing import Any

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.domain.attack_surface.enums import AssessmentStatus as SurfaceAssessmentStatus
from hunterx.domain.attack_surface.enums import SurfaceLayer, VerificationState
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_execution.models import (
    CapabilityExecutionRecord,
    ToolExecutionRecord,
    build_capability_coverage,
)
from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
from hunterx.domain.vulnerability_capability.models import ProbeVerdict
from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Probe-able surface layers (structural target/asset/service nodes carry no
#: probeable input; their children do).
_PROBE_LAYERS = (
    SurfaceLayer.SURFACE,
    SurfaceLayer.INPUT,
    SurfaceLayer.OBJECT,
    SurfaceLayer.WORKFLOW,
)

#: Tool fallback chains per capability family: a specialized scanner is
#: attempted first; when it is unavailable the chain falls through to the
#: native HunterX differential strategy (always present). Absence is recorded
#: explicitly — a capability is never silently marked complete.
DEFAULT_FALLBACK_CHAINS: dict[str, tuple[str, ...]] = {
    "sql-injection": ("sqlmap", "ghauri"),
    "nosql-injection": ("sqlmap",),
    "xss": ("dalfox", "xsstrike"),
    "command-injection": ("commix",),
    "ssti": ("sstimap", "tplmap"),
    "xxe": ("xxeinjector",),
    "lfi": (),
    "ssrf": (),
    "open-redirect": (),
    "idor": (),
    "authentication": (),
    "authorization": (),
    "api-security": (),
    "graphql-security": (),
    "cors-misconfiguration": (),
    "sensitive-info-exposure": (),
    "security-misconfiguration": (),
    "known-vulnerable-component": (),
    "dependency-vulnerability": (),
    "cloud-exposure": (),
    "http-access-differential": (),
}

#: Recognized dependency vulnerabilities reported by the platform scanners.
_DEPENDENCY_TOOL_IDS = (
    "retire-js",
    "osv-scanner",
    "nancy",
    "trivy",
    "dependency-check",
    "safety",
    "pip-audit",
)


class CapabilityExecutionEngine:
    """Execute queued capability tasks with real, bounded differential probes."""

    def __init__(
        self,
        *,
        mission_id: str = "",
        target_key: str = "",
        surface: AttackSurfaceService,
        capability_engine: VulnerabilityCapabilityEngine | None = None,
        probe_executor: ProbeExecutor | None = None,
        adaptive: AdaptiveAttackService | None = None,
        execution_engine: Any = None,
        fallback_chains: dict[str, tuple[str, ...]] | None = None,
        probe_timeout_s: float = 6.0,
        max_tasks: int = 0,
    ) -> None:
        self.mission_id = mission_id or f"phase5-{generate_id()[:8]}"
        self.target_key = target_key
        self.surface = surface
        self._capability_engine = capability_engine or VulnerabilityCapabilityEngine()
        self._probe_executor = probe_executor or ProbeExecutor(timeout_s=probe_timeout_s)
        self.adaptive = adaptive
        self.execution_engine = execution_engine
        self.fallback_chains = dict(fallback_chains or DEFAULT_FALLBACK_CHAINS)
        self.max_tasks = max_tasks
        self.records: list[CapabilityExecutionRecord] = []
        self._tool_records: list[ToolExecutionRecord] = []
        self._probe_count = 0

    # -- public API ---------------------------------------------------------

    def execute_ready(self, *, max_tasks: int = 0, session: Any = None) -> dict[str, Any]:
        """Execute every ready queue task (optionally capped).

        Args:
            max_tasks: hard cap on executed tasks (``0`` = no cap).
            session: an established :class:`AuthenticatedSession` to execute
                the auth-context matrix (``None`` = anonymous only).

        Returns:
            A summary of executed tasks, probes, records and queue state.

        """
        executed = 0
        probes = 0
        for task in self.surface.queue.ready():
            if (max_tasks or self.max_tasks) and executed >= (max_tasks or self.max_tasks):
                break
            node = self.surface.graph.node(task.surface_key)
            if node is None or node.layer not in _PROBE_LAYERS:
                self._record_not_applicable(task, node, "structural surface without a probeable input")
                continue
            for session_state in ("anonymous", "authenticated"):
                if session_state == "authenticated" and (session is None or not getattr(session, "established", False)):
                    continue
                record = self._execute_task(task, node, session_state=session_state, session=session if session_state == "authenticated" else None)
                self.records.append(record)
                probes += record.requests
            executed += 1
        return {
            "tasks_executed": executed,
            "requests_sent": probes,
            "records": len(self.records),
            "findings": sum(1 for r in self.records if r.outcome is CapabilityExecutionStatus.FINDING),
            "queue_remaining": self.surface.queue.remaining(),
        }

    def coverage(
        self,
        *,
        catalog: list[str] | None = None,
        mission_id: str = "",
        target: str = "",
    ) -> dict[str, Any]:
        """Build the mission's authoritative capability-coverage document.

        Every capability in the live catalog receives exactly one status —
        never a catalog-only claim.
        """
        if catalog is None:
            catalog = list(self._catalog_ids())
        mapped = {assignment.capability_id for assignment in self.surface.graph.assignments()}
        queued = {task.capability_id for task in self.surface.queue.tasks()}
        return build_capability_coverage(
            self.records,
            catalog,
            mapped_capabilities=mapped,
            queued_capabilities=queued,
            mission_id=mission_id or self.mission_id,
            target=target or self.target_key,
        )

    def write_coverage(self, path: str | pathlib.Path, **kwargs: Any) -> pathlib.Path:
        """Persist the mission's ``capability_coverage.json`` artifact."""
        destination = pathlib.Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(self.coverage(**kwargs), indent=1), encoding="utf-8")
        return destination

    def catalog(self) -> list[str]:
        """Return the registered capability ids (the live catalog)."""
        return list(self._catalog_ids())

    # -- internals ----------------------------------------------------------

    def _catalog_ids(self) -> set[str]:
        """Capability ids from the platform catalog (registration, not claims)."""
        from hunterx.domain.vulnerability_capability.registry import capabilities

        return {capability.vulnerability_class for capability in capabilities()}

    def _evidence_for(self, node: Any) -> dict[str, Any]:
        """Build capability evidence from a surface node (endpoint-aware)."""
        context = node.context
        parameter = node.name if node.layer is SurfaceLayer.INPUT else str(node.attributes.get("parameter") or "")
        endpoint = node.name
        if node.layer is SurfaceLayer.INPUT:
            parent = self.surface.graph.parent(node.key)
            if parent is not None:
                endpoint = parent.name
        return {
            "target": self.target_key,
            "endpoint": endpoint,
            "parameter": parameter,
            "confidence": node.confidence,
            "method": getattr(context, "method", ""),
            "content_type": getattr(context, "content_type", ""),
            "fetch_hint": getattr(context, "fetch_hint", False),
            "object_hint": getattr(context, "object_hint", False),
            "observed_status": str(node.attributes.get("observed_status") or ""),
        }

    def _execute_task(
        self,
        task: Any,
        node: Any,
        *,
        session_state: str,
        session: Any,
    ) -> CapabilityExecutionRecord:
        """Run one ``(surface, capability, context)`` execution."""
        capability_id = task.capability_id
        evidence = self._evidence_for(node)
        base_record = CapabilityExecutionRecord(
            mission_id=self.mission_id,
            capability_id=capability_id,
            surface_key=task.surface_key,
            endpoint=evidence.get("endpoint", ""),
            vector=evidence.get("parameter", ""),
            session_state=session_state,
            chain=(task.surface_key, capability_id),
        )
        capability = self._capability_engine_capability(capability_id)
        if capability is None:
            return self._settle(base_record, CapabilityExecutionStatus.FAILED, "capability not registered in the catalog", task, node)

        applicability = capability.can_apply(evidence)
        if not applicability.applicable:
            return self._settle(base_record, CapabilityExecutionStatus.NOT_APPLICABLE, applicability.reason or "capability does not apply to this surface", task, node)

        probes = self._build_probes(capability_id, evidence, capability)
        if not probes:
            return self._settle(base_record, CapabilityExecutionStatus.BLOCKED, f"no probe constructible for {capability_id} on this surface", task, node)

        tools = self._attempt_tool_chain(capability_id, evidence, session)
        strategies = self._strategy_labels(probes)

        if self.adaptive is not None:
            # Let the adaptive controller observe/plan the probe (pacing side
            # effect); the probes themselves carry the capability strategy.
            self.adaptive.plan_probe(
                surface=node,
                capability_id=capability_id,
                payloads=tuple(probes[0].payloads),
                baseline_payload=probes[0].baseline_payload,
            )

        verdicts: list[ProbeVerdict] = []
        response_sets: list[list[dict[str, Any]]] = []
        try:
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.RUNNING)
            for probe in probes:
                probe = self._with_session(probe, session)
                responses = self._probe_executor.execute(probe, target=evidence["endpoint"])
                self._probe_count += 1
                self._observe(responses)
                response_sets.append(responses)
                verdicts.append(self._capability_engine.analyze_probe(capability_id, probe, responses))
        except PermissionError as exc:
            return self._settle(
                base_record, CapabilityExecutionStatus.BLOCKED,
                f"probe refused: {exc}", task, node,
                tools=tools, strategies=strategies,
            )
        except Exception as exc:  # noqa: BLE001 - recorded as a bounded failure
            return self._settle(
                base_record, CapabilityExecutionStatus.FAILED,
                str(exc)[:300], task, node,
                tools=tools, strategies=strategies,
            )

        base_record = _replace(
            base_record,
            confidence=float(evidence.get("confidence") or 0.0) or None,
            request_summaries=self._request_summaries(probes),
            response_summaries=self._response_summaries(response_sets),
        )
        verdict, outcome, reason = self._combine_verdicts(verdicts, capability_id)
        tools = tools + self._tool_record_native(probes, verdict, evidence)
        return self._settle(
            base_record, outcome, reason, task, node,
            tools=tools, strategies=strategies, verdict=verdict, requests=self._requests_for(probes),
        )

    def _capability_engine_capability(self, capability_id: str) -> Any:
        """Resolve the capability instance (``None`` when unregistered)."""
        from hunterx.domain.vulnerability_capability.registry import capability_for

        return capability_for(capability_id)

    def _build_probes(self, capability_id: str, evidence: dict[str, Any], capability: Any) -> list[Any]:
        """Build every targeted probe (multi-vector, one per signal strategy).

        Falls back to the engine's single-probe path when the capability does
        not expose its probe list directly.
        """
        try:
            probes = list(capability.build_probes(evidence))
        except Exception:  # noqa: BLE001 - degrade to the engine path
            probes = []
        if not probes:
            probe = self._capability_engine.build_probe(capability_id, evidence)
            if probe is not None:
                probes = [probe]
        return probes

    def _strategy_labels(self, probes: list[Any]) -> tuple[str, ...]:
        """Record the multi-strategy labels actually used by the probes.

        Every probe contributes its differential signal family, its payload
        family (payload count), and any controlled mutations / body-template
        vectors — never an assumed strategy.
        """
        labels: list[str] = []
        for probe in probes:
            signal = getattr(probe, "analysis", None)
            labels.append(signal.value if signal is not None and getattr(signal, "value", None) else "differential")
            payload_count = len(getattr(probe, "payloads", ()) or ())
            labels.append(f"{payload_count}-payload-family" if payload_count > 1 else "single-payload")
            if getattr(probe, "mutations", ()):
                labels.append("controlled-mutation")
            if getattr(probe, "body_template", ""):
                labels.append("body-template")
        return tuple(dict.fromkeys(labels))

    def _attempt_tool_chain(self, capability_id: str, evidence: dict[str, Any], session: Any) -> tuple[ToolExecutionRecord, ...]:
        """Attempt the capability's tool chain; record every step honestly.

        Scanner -> scanner -> native strategy. A scanner that is absent is
        recorded ``unavailable`` (never fabricated); the chain then falls
        through to the native differential strategy in :meth:`_execute_task`.
        """
        records: list[ToolExecutionRecord] = []
        for tool_id in self.fallback_chains.get(capability_id, ()):
            endpoint = str(evidence.get("endpoint") or "")
            if self.execution_engine is None or self.execution_engine.adapter_for(tool_id) is None:
                records.append(
                    ToolExecutionRecord(
                        tool_id=tool_id,
                        surface=endpoint,
                        stdout_status="unavailable",
                        parsed_result=None,
                        duration_ms=0,
                        strategy="scanner",
                        error="adapter not available — falling through to the native strategy",
                    )
                )
                continue
            try:
                from hunterx.tools.sdk.context import ExecutionContextBuilder

                builder = ExecutionContextBuilder()
                context = (
                    builder.with_mission(self.mission_id)
                    .with_target_type("url")
                    .with_tool(tool_id)
                    .with_target(endpoint)
                    .with_permissions(("network",))
                    .with_timeout(30.0)
                    .with_parameters({"url": endpoint})
                    .build()
                )
                started = __import__("time").monotonic()
                pipeline = self.execution_engine.execute(context)
                duration_ms = int((__import__("time").monotonic() - started) * 1000)
                result = pipeline.result
                stdout_status = "ok" if result.ok else ("failed" if result.status.value == "failed" else "no-output")
                records.append(
                    ToolExecutionRecord(
                        tool_id=tool_id,
                        surface=endpoint,
                        command=str(getattr(pipeline, "command", "") or ""),
                        exit_code=result.output.exit_code if result.output else None,
                        stdout_status=stdout_status,
                        parsed_result=bool(result.ok),
                        duration_ms=duration_ms,
                        strategy="scanner",
                        error=str(result.error or "")[:200],
                    )
                )
                if result.ok:
                    break
            except Exception as exc:  # noqa: BLE001 - honest failure record
                records.append(
                    ToolExecutionRecord(
                        tool_id=tool_id,
                        surface=endpoint,
                        stdout_status="failed",
                        parsed_result=False,
                        duration_ms=0,
                        strategy="scanner",
                        error=str(exc)[:200],
                    )
                )
        return tuple(records)

    def _with_session(self, probe: Any, session: Any) -> Any:
        """Attach the authenticated session's cookies to a probe (frozen-safe)."""
        if session is None:
            return probe
        headers = list(probe.headers or ())
        cookie = getattr(session, "cookie_header", None)
        value = cookie() if callable(cookie) else str(getattr(session, "cookies", "") or "")
        if value:
            headers = [(name, val) for name, val in headers if name.lower() != "cookie"]
            headers.append(("Cookie", value))
        return _replace(probe, headers=tuple(headers))

    def _observe(self, responses: list[dict[str, Any]]) -> None:
        """Feed defensive signals into the adaptive controller (never a verdict)."""
        if self.adaptive is None:
            return
        statuses = [int(r.get("status") or 0) for r in responses if isinstance(r, dict)]
        status = next((s for s in (429, 403) if s in statuses), max((s for s in statuses if s >= 500), default=None))
        elapsed = sum(int(r.get("elapsed_ms") or 0) for r in responses if isinstance(r, dict))
        self.adaptive.observe(status_code=status, duration_ms=elapsed, source="capability-execution")

    def _combine_verdicts(self, verdicts: list[ProbeVerdict], capability_id: str) -> tuple[ProbeVerdict, CapabilityExecutionStatus, str]:
        """Combine multi-vector verdicts into one honest outcome.

        Any supported verdict is a FINDING; every probe contradicted is a
        VERIFIED definite negative; otherwise the execution was uninformative
        (NO_FINDING — tested, no signal).
        """
        if not verdicts:
            return ProbeVerdict(uninformative=True, notes=f"no verdicts for {capability_id}"), CapabilityExecutionStatus.NO_FINDING, "probe produced no verdicts"
        supported = [verdict for verdict in verdicts if verdict.supported]
        if supported:
            return supported[0], CapabilityExecutionStatus.FINDING, f"{capability_id} signal observed ({supported[0].signal.value})"
        if all(verdict.contradicted for verdict in verdicts):
            return verdicts[0], CapabilityExecutionStatus.VERIFIED, f"definite negative verdict for {capability_id} across all vectors"
        return verdicts[0], CapabilityExecutionStatus.NO_FINDING, f"no definitive signal for {capability_id} (uninformative)"

    def _requests_for(self, probes: list[Any]) -> int:
        return sum(1 + len(probe.payloads) + len(probe.mutations) for probe in probes)

    def _request_summaries(self, probes: list[Any]) -> tuple[dict[str, Any], ...]:
        """Retain the probe requests (headers excluded - they may carry cookies)."""
        summaries: list[dict[str, Any]] = []
        for probe in probes:
            body = str(getattr(probe, "body", "") or "")
            summaries.append(
                {
                    "method": getattr(probe, "method", "GET") or "GET",
                    "url": getattr(probe, "endpoint", "") or "",
                    "parameter": getattr(probe, "parameter", "") or "",
                    "baseline_payload": getattr(probe, "baseline_payload", "") or "",
                    "payloads": list(getattr(probe, "payloads", ()) or ()),
                    "mutations": list(getattr(probe, "mutations", ()) or ()),
                    "body": body[:400],
                }
            )
        return tuple(summaries)

    def _response_summaries(self, response_sets: list[list[dict[str, Any]]]) -> tuple[dict[str, Any], ...]:
        """Retain bounded response evidence (status, length, truncated body)."""
        summaries: list[dict[str, Any]] = []
        for responses in response_sets:
            for response in responses or []:
                body = str(response.get("body", "") or "")
                summaries.append(
                    {
                        "status": response.get("status"),
                        "length": len(body),
                        "body_snippet": body[:300],
                        "elapsed_ms": response.get("elapsed_ms", 0),
                        "url": response.get("url", ""),
                    }
                )
        return tuple(summaries)

    def _tool_record_native(self, probes: list[Any], verdict: ProbeVerdict, evidence: dict[str, Any]) -> tuple[ToolExecutionRecord, ...]:
        """Record the native differential strategy execution."""
        return (
            ToolExecutionRecord(
                tool_id="hunterx-differential",
                surface=str(evidence.get("endpoint") or ""),
                command="; ".join(f"{probe.method or 'GET'} {probe.endpoint}" for probe in probes[:4]),
                exit_code=0,
                stdout_status="ok",
                parsed_result=verdict.signal.value,
                duration_ms=0,
                strategy="native-differential",
            ),
        )

    def _settle(
        self,
        record: CapabilityExecutionRecord,
        outcome: CapabilityExecutionStatus,
        reason: str,
        task: Any,
        node: Any,
        *,
        tools: tuple[ToolExecutionRecord, ...] = (),
        strategies: tuple[str, ...] = (),
        verdict: ProbeVerdict | None = None,
        requests: int = 0,
    ) -> CapabilityExecutionRecord:
        """Record the outcome and settle the queue task + assignment."""
        from dataclasses import replace as _replace

        settled = _replace(
            record,
            outcome=outcome,
            reason=reason,
            tools=tools,
            strategies=strategies,
            requests=requests,
            verification_attempts=1 if verdict is not None else 0,
            findings=1 if outcome is CapabilityExecutionStatus.FINDING else 0,
            evidence=dict(verdict.evidence) if verdict is not None else {},
            chain=(*record.chain, outcome.value),
        )
        if outcome is CapabilityExecutionStatus.NOT_APPLICABLE:
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.SKIPPED)
            self.surface.queue.settle(task.task_id, VerificationState.NOT_APPLICABLE)
            self._settle_assignment(node, task.capability_id, VerificationState.NOT_APPLICABLE, outcome.value)
        elif outcome is CapabilityExecutionStatus.BLOCKED:
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.BLOCKED)
            self.surface.queue.settle(task.task_id, VerificationState.INCONCLUSIVE)
            self._settle_assignment(node, task.capability_id, VerificationState.INCONCLUSIVE, outcome.value)
        elif outcome is CapabilityExecutionStatus.FAILED:
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.FAILED)
            self.surface.queue.settle(task.task_id, VerificationState.INCONCLUSIVE)
            self._settle_assignment(node, task.capability_id, VerificationState.INCONCLUSIVE, outcome.value)
        elif outcome is CapabilityExecutionStatus.FINDING:
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.COMPLETED)
            self.surface.queue.settle(task.task_id, VerificationState.VERIFIED)
            self._settle_assignment(node, task.capability_id, VerificationState.VERIFIED, outcome.value)
        else:
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.COMPLETED)
            self.surface.queue.settle(
                task.task_id,
                VerificationState.VERIFIED if outcome is CapabilityExecutionStatus.VERIFIED else VerificationState.INCONCLUSIVE,
            )
            self._settle_assignment(
                node,
                task.capability_id,
                VerificationState.VERIFIED if outcome is CapabilityExecutionStatus.VERIFIED else VerificationState.INCONCLUSIVE,
                outcome.value,
            )
        return settled

    def _record_not_applicable(self, task: Any, node: Any, reason: str) -> None:
        """Record a structural-surface NOT_APPLICABLE and settle the task."""
        record = CapabilityExecutionRecord(
            mission_id=self.mission_id,
            capability_id=task.capability_id,
            surface_key=task.surface_key,
            endpoint=node.name if node is not None else task.surface_key,
            session_state="anonymous",
            outcome=CapabilityExecutionStatus.NOT_APPLICABLE,
            reason=reason,
            chain=(task.surface_key, task.capability_id, "not-applicable"),
        )
        self.records.append(record)
        self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.SKIPPED)
        self.surface.queue.settle(task.task_id, VerificationState.NOT_APPLICABLE)
        if node is not None:
            self._settle_assignment(node, task.capability_id, VerificationState.NOT_APPLICABLE, "not-applicable")

    def _settle_assignment(self, node: Any, capability_id: str, verification: VerificationState, outcome: str) -> None:
        """Settle the matching capability assignment for a surface."""
        for assignment in self.surface.graph.assignments_for(node.key):
            if assignment.capability_id == capability_id:
                assignment.mark(SurfaceAssessmentStatus.COMPLETED)
                assignment.settle(verification)
                assignment.record_evidence(
                    {"outcome": outcome, "at": utcnow_iso(), "task_capability": capability_id}
                )


__all__ = ["CapabilityExecutionEngine", "DEFAULT_FALLBACK_CHAINS"]
