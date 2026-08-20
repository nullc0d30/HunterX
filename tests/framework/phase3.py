# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 3 validation harness.

Drives HunterX's real engine (attack-surface model + capability mapping +
assessment queue + adaptive attack control + differential verification +
completion gate) against a target and produces the full Phase 3 evidence:

    * generic pipeline metrics (assets, services, routes, inputs, objects,
      workflows, auth contexts, surfaces, capabilities, tasks, verification,
      findings, blocked/failed, new surfaces during attack),
    * a capability-coverage matrix sourced from the live catalog,
    * an attack-surface exhaustion / completion-gate proof with a
      machine-readable completion reason and a queue dump,
    * adaptive control behavior (rate, concurrency, defensive signals,
      backoff/recovery events).

The harness never hardcodes a target: discovery observations come from the
caller (fixture feeds or a real crawl), and every attack/verification step is a
real loopback differential probe. A target that is not loopback is honestly
marked blocked — never fabricated.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService, CapabilityCatalog
from hunterx.domain.adaptive_attack.enums import AttackOutcome
from hunterx.domain.attack_surface.enums import AssessmentStatus as SurfaceAssessmentStatus
from hunterx.domain.attack_surface.enums import SurfaceLayer, VerificationState
from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Probe-able surface layers (structural target/asset/service nodes are not
#: directly probed; their children carry the inputs).
_PROBE_LAYERS = (
    SurfaceLayer.SURFACE,
    SurfaceLayer.INPUT,
    SurfaceLayer.OBJECT,
    SurfaceLayer.WORKFLOW,
)


class Phase3Harness:
    """Run and measure the full target-agnostic assessment pipeline.

    Args:
        target: authorized target key.
        mission_id: owning mission id (``""`` generates one).
        probe_timeout_s: per-probe request timeout.
        max_tasks: optional hard cap on probe executions (honest bound).

    """

    def __init__(
        self,
        *,
        target: str,
        mission_id: str = "",
        probe_timeout_s: float = 6.0,
        max_tasks: int = 0,
    ) -> None:
        self.target = target
        self.mission_id = mission_id or f"phase3-{generate_id()[:8]}"
        self.max_tasks = max_tasks
        self.surface = AttackSurfaceService(mission_id=self.mission_id, target_key=target)
        self.adaptive = AdaptiveAttackService(mission_id=self.mission_id, target_key=target, enforce_pacing=False)
        self.catalog = list(CapabilityCatalog.from_platform())
        self._probe_executor = ProbeExecutor(timeout_s=probe_timeout_s)
        self._cap_engine = VulnerabilityCapabilityEngine()
        self._probe_count = 0
        self._probe_budget = 0
        self.verdicts: list[dict[str, Any]] = []
        self.findings: list[dict[str, Any]] = []
        self.candidates: list[dict[str, Any]] = []
        self.feedback_samples: list[dict[str, Any]] = []
        self.executed_tasks: list[dict[str, Any]] = []
        self.blocked_tasks: list[dict[str, Any]] = []
        self.failed_tasks: list[dict[str, Any]] = []

    # -- discovery intake ---------------------------------------------------

    def ingest(
        self,
        *,
        observation_type: str,
        content: Any,
        asset_key: str,
        session_state: str = "",
        source: str = "phase3",
    ) -> dict[str, Any]:
        """Feed one discovery observation into the surface model."""
        return self.surface.on_observation(
            observation_type=observation_type,
            content=content,
            asset_key=asset_key,
            source=source,
            session_state=session_state,
        )

    # -- attack / verification ---------------------------------------------

    def _evidence_for(self, surface: Any) -> dict[str, Any]:
        """Build capability evidence from a surface node (endpoint-aware)."""
        context = surface.context
        parameter = surface.name if surface.layer is SurfaceLayer.INPUT else str(surface.attributes.get("parameter") or "")
        endpoint = surface.name
        if surface.layer is SurfaceLayer.INPUT:
            parent = self.surface.graph.parent(surface.key)
            if parent is not None:
                endpoint = parent.name
        evidence: dict[str, Any] = {
            "target": self.target,
            "endpoint": endpoint,
            "parameter": parameter,
            "confidence": surface.confidence,
            "method": context.method,
            "content_type": context.content_type,
            "fetch_hint": context.fetch_hint,
            "object_hint": context.object_hint,
            "observed_status": str(surface.attributes.get("observed_status") or ""),
        }
        return evidence

    def attack_queue(self) -> dict[str, Any]:
        """Execute the queued assessment tasks with real differential probes.

        Drains the Phase 1 assessment queue through the Phase 2 adaptive engine:
        each ready task builds a bounded probe plan, runs a real loopback
        differential probe, classifies the verdict, settles the task and feeds
        the adaptive controller. Honest outcomes: supported/contradicted/
        uninformative (verification), blocked (non-loopback), failed (probe
        error), or left queued when a task cap applies.
        """
        executed = 0
        probes = 0
        for task in self.surface.queue.ready():
            if self.max_tasks and executed >= self.max_tasks:
                break
            node = self.surface.graph.node(task.surface_key)
            if node is None or node.layer not in _PROBE_LAYERS:
                continue
            outcome = self._execute_task(task, node)
            executed += 1
            probes += outcome.get("requests", 0)
            if outcome["outcome"] == AttackOutcome.SUPPORTED.value:
                self.findings.append(outcome)
            elif outcome["outcome"] in (AttackOutcome.CONTRADICTED.value, AttackOutcome.UNINFORMATIVE.value):
                self.candidates.append(outcome)
        self._probe_count += probes
        return {
            "tasks_executed": executed,
            "requests_sent": probes,
            "findings": len(self.findings),
            "candidates": len(self.candidates),
            "queue_remaining": self.surface.queue.remaining(),
        }

    def _execute_task(self, task: Any, node: Any) -> dict[str, Any]:
        """Run one differential probe for ``(surface, capability)``."""
        record: dict[str, Any] = {
            "task_id": task.task_id,
            "surface_key": task.surface_key,
            "kind": node.kind_value(),
            "endpoint": node.name,
            "parameter": task.context.method or "",
            "capability": task.capability_id,
            "outcome": AttackOutcome.DEFERRED.value,
            "signal": "",
            "requests": 0,
            "evidence": {},
            "notes": "",
        }
        evidence = self._evidence_for(node)
        try:
            probe = self._cap_engine.build_probe(task.capability_id, evidence)
            if probe is None:
                self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.SKIPPED)
                self.surface.queue.settle(task.task_id, VerificationState.NOT_APPLICABLE)
                record["outcome"] = AttackOutcome.DEFERRED.value
                record["notes"] = f"no probe constructible for {task.capability_id} on this surface"
                self._settle_assignment(node, task.capability_id, VerificationState.NOT_APPLICABLE, AttackOutcome.DEFERRED.value)
                self.blocked_tasks.append(record)
                return record
            # Plan the probe through the adaptive engine (bounded aggression).
            plan = self.adaptive.plan_probe(
                surface=node,
                capability_id=task.capability_id,
                payloads=tuple(probe.payloads),
                baseline_payload=probe.baseline_payload,
            )
            record["requests"] = 1 + len(plan.payloads) + len(plan.mutations)
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.RUNNING)
            responses = self._probe_executor.execute(probe, target=evidence["endpoint"])
            self._feed_probe_responses(responses)
            # Adaptive feedback: every probe's defensive signals throttle the
            # engine — a 429/403/5xx is target behavior, never a verdict.
            self.adaptive.observe(
                status_code=_max_status(responses),
                duration_ms=_total_ms(responses),
                source="probe",
            )
            verdict = self._cap_engine.analyze_probe(task.capability_id, probe, responses)
            record["signal"] = verdict.signal.value
            record["evidence"] = verdict.evidence
            record["notes"] = verdict.notes
            record["plan"] = plan.to_dict()
            self.executed_tasks.append(record)
            if verdict.supported:
                record["outcome"] = AttackOutcome.SUPPORTED.value
                self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.COMPLETED)
                self.surface.queue.settle(task.task_id, VerificationState.VERIFIED)
                self._settle_assignment(node, task.capability_id, VerificationState.VERIFIED, AttackOutcome.SUPPORTED.value)
            elif verdict.contradicted:
                record["outcome"] = AttackOutcome.CONTRADICTED.value
                self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.COMPLETED)
                self.surface.queue.settle(task.task_id, VerificationState.NOT_APPLICABLE)
                self._settle_assignment(node, task.capability_id, VerificationState.NOT_APPLICABLE, AttackOutcome.CONTRADICTED.value)
            else:
                record["outcome"] = AttackOutcome.UNINFORMATIVE.value
                self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.COMPLETED)
                self.surface.queue.settle(task.task_id, VerificationState.INCONCLUSIVE)
                self._settle_assignment(node, task.capability_id, VerificationState.INCONCLUSIVE, AttackOutcome.UNINFORMATIVE.value)
            self.verdicts.append(record)
            return record
        except PermissionError:
            # Non-loopback target: the probe is honestly refused — blocking is
            # blocking, never a finding or a silent skip.
            record["outcome"] = AttackOutcome.BLOCKED.value
            record["notes"] = "probe refused: target is not a loopback target"
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.BLOCKED)
            self.surface.queue.settle(task.task_id, VerificationState.INCONCLUSIVE)
            self._settle_assignment(node, task.capability_id, VerificationState.INCONCLUSIVE, AttackOutcome.BLOCKED.value)
            self.blocked_tasks.append(record)
            self.adaptive.observe(status_code=403, source="probe")
            return record
        except Exception as exc:  # noqa: BLE001 - recorded as a bounded failure
            record["outcome"] = AttackOutcome.ERROR.value
            record["notes"] = str(exc)[:300]
            self.surface.queue.mark(task.task_id, SurfaceAssessmentStatus.FAILED)
            self.surface.queue.settle(task.task_id, VerificationState.INCONCLUSIVE)
            self._settle_assignment(node, task.capability_id, VerificationState.INCONCLUSIVE, AttackOutcome.ERROR.value)
            self.failed_tasks.append(record)
            self.adaptive.observe(status_code=0, error=str(exc)[:200], source="probe")
            return record

    def _settle_assignment(self, node: Any, capability_id: str, verification: VerificationState, outcome: str) -> None:
        """Settle the matching capability assignment for a surface."""
        for assignment in self.surface.graph.assignments_for(node.key):
            if assignment.capability_id == capability_id:
                assignment.mark(SurfaceAssessmentStatus.COMPLETED)
                assignment.settle(verification)
                assignment.record_evidence(
                    {"outcome": outcome, "at": utcnow_iso(), "task_capability": capability_id}
                )

    def _feed_probe_responses(self, responses: list[dict[str, Any]]) -> None:
        """Record probe responses as raw adaptive-feedback samples."""
        for response in responses:
            if not isinstance(response, dict):
                continue
            self.feedback_samples.append(
                {
                    "status": response.get("status"),
                    "elapsed_ms": response.get("elapsed_ms"),
                    "error": str(response.get("error") or "")[:200],
                }
            )

    # -- real black-box discovery (no target preconfiguration) ---------------

    def real_discovery(self, *, max_scripts: int = 4, max_endpoints: int = 60) -> dict[str, Any]:
        """Discover a real target using HunterX's in-process crawler + JS analyzer.

        The target's SPA root is crawled and its script bundles are analyzed
        with the platform JavaScript analyzer; the resulting API endpoints,
        routes and query parameters are fed into the surface model exactly like
        any discovery observation. No target-specific route or parameter is
        preconfigured.
        """
        import re
        import urllib.parse
        import urllib.request
        from urllib.parse import urljoin, urlsplit

        from hunterx.domain.execution import ExecutionContext
        from hunterx.tools.javascript.analyzer import JavaScriptAnalyzerAdapter
        from hunterx.tools.sdk.engine import ExecutionEngine
        from hunterx.tools.web.crawler import CrawlerAdapter

        engine = ExecutionEngine()
        engine.register_adapter("crawler", CrawlerAdapter())
        engine.register_adapter("javascript-analyzer", JavaScriptAnalyzerAdapter())
        engine.install_hook("crawler", lambda *_: "1.0")
        engine.install_hook("javascript-analyzer", lambda *_: "1.0")
        engine.install("crawler")
        engine.install("javascript-analyzer")

        discovered_urls: list[str] = []
        discovered_routes: list[str] = []
        crawled = 0

        # 1) Crawl the SPA root with HunterX's crawler.
        crawl_context = ExecutionContext(
            execution_id=f"{self.mission_id}-crawl",
            tool_id="crawler",
            target=self.target,
            mission_id=self.mission_id,
            permissions=("network",),
            parameters={"depth": 1, "max_pages": 15, "respect_robots": False, "timeout": 6},
        )
        crawl_result = engine.execute(crawl_context).result
        if crawl_result.ok:
            crawl_data = (crawl_result.output.json or {}).get("crawl") or {}
            crawled = int(crawl_result.output.json.get("count") or 0)
            for item in crawl_data.get("urls") or ():
                url = item.get("url") if isinstance(item, dict) else item
                if url:
                    discovered_urls.append(str(url))
            for item in crawl_data.get("endpoints") or ():
                url = item.get("url") if isinstance(item, dict) else item
                if url:
                    discovered_urls.append(str(url))

        # 2) Locate the SPA script bundles (real fetch of the index page).
        scripts: list[str] = []
        try:
            html = urllib.request.urlopen(self.target, timeout=8).read().decode("utf-8", "replace")
            scripts = list(dict.fromkeys(re.findall(r"""<script[^>]+src=["']([^"']+)""", html)))
        except Exception:  # noqa: BLE001 - discovery degrades to crawl-only
            scripts = []

        # 3) Analyze each script bundle for API endpoints / routes.
        for script in scripts[:max_scripts]:
            script_url = urljoin(self.target, script)
            if urlsplit(script_url).netloc != urlsplit(self.target).netloc:
                continue
            js_context = ExecutionContext(
                execution_id=f"{self.mission_id}-js",
                tool_id="javascript-analyzer",
                target=script_url,
                mission_id=self.mission_id,
                permissions=("network",),
                parameters={"url": script_url},
            )
            js_result = engine.execute(js_context).result
            if not js_result.ok:
                continue
            analysis = ((js_result.output.json or {}).get("javascript") or {}).get("analyses") or []
            if not analysis:
                continue
            data = analysis[0]
            for endpoint in data.get("endpoints") or ():
                url = endpoint.get("url") if isinstance(endpoint, dict) else endpoint
                if url:
                    discovered_urls.append(urljoin(self.target, str(url)))
            for route in data.get("routes") or ():
                value = route.get("route") if isinstance(route, dict) else route
                if value:
                    discovered_routes.append(str(value))

        # 4) Feed everything into the surface model (same-origin only).
        seen: set[str] = set()
        endpoints: list[str] = []
        api_candidates = [*discovered_urls, *discovered_routes]
        for url in api_candidates:
            absolute = urljoin(self.target, url)
            if urlsplit(absolute).netloc != urlsplit(self.target).netloc:
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            endpoints.append(absolute)
            if len(endpoints) >= max_endpoints:
                break
        if endpoints:
            self.ingest(
                observation_type="api",
                content={"endpoints": endpoints},
                asset_key=self.target,
                source="real-js-analysis",
            )
        for route in list(dict.fromkeys(discovered_routes))[:max_endpoints]:
            self.ingest(
                observation_type="client_route",
                content={"routes": [urljoin(self.target, route)]},
                asset_key=self.target,
                source="real-js-analysis",
            )

        # 5) Extract query parameters from discovered endpoint URLs.
        parameters = sorted(
            {
                key
                for url in endpoints
                for key, _ in urllib.parse.parse_qsl(urlsplit(url).query, keep_blank_values=True)
                if key
            }
        )
        if parameters:
            self.ingest(
                observation_type="parameter",
                content={"parameters": parameters},
                asset_key=self.target,
                source="real-js-analysis",
            )

        return {
            "crawl_count": crawled,
            "scripts_analyzed": len(scripts[:max_scripts]),
            "endpoints_discovered": len(endpoints),
            "routes_discovered": len(discovered_routes),
            "parameters_discovered": len(parameters),
            "parameters": parameters,
        }

    # -- measurement --------------------------------------------------------

    def surface_metrics(self) -> dict[str, Any]:
        """Collect the generic pipeline surface metrics."""
        graph = self.surface.graph
        kinds = Counter(node.kind_value() for node in graph.nodes())
        return {
            "target": self.target,
            "assets_discovered": sum(kinds.get(k, 0) for k in ("host", "subdomain", "ip")),
            "services_discovered": sum(kinds.get(k, 0) for k in ("service", "port")),
            "applications_discovered": sum(kinds.get(k, 0) for k in ("technology",)),
            "routes_discovered": sum(kinds.get(k, 0) for k in ("route", "endpoint", "url", "api_endpoint", "graphql_operation", "websocket")),
            "inputs_discovered": sum(kinds.get(k, 0) for k in ("parameter", "json_field", "form_field", "header", "cookie", "path_variable", "file", "upload", "download")),
            "objects_discovered": sum(kinds.get(k, 0) for k in ("object", "object_identifier")),
            "workflows_discovered": sum(kinds.get(k, 0) for k in ("workflow", "state_transition")),
            "auth_contexts_discovered": sum(kinds.get(k, 0) for k in ("auth_surface", "auth_state", "authorization_context")),
            "client_surfaces_discovered": sum(kinds.get(k, 0) for k in ("client_route", "javascript_endpoint", "sink", "source")),
            "attack_surfaces_discovered": graph.node_count(),
            "kinds_by_count": dict(kinds),
        }

    def task_metrics(self) -> dict[str, Any]:
        """Collect assessment-queue / task metrics."""
        queue = self.surface.queue
        statuses = Counter(task.status.value for task in queue.tasks())
        return {
            "capabilities_considered": len({assignment.capability_id for assignment in self.surface.graph.assignments()}),
            "tasks_generated": queue.total(),
            "tasks_executed": len(self.executed_tasks),
            "tasks_blocked": len(self.blocked_tasks),
            "tasks_failed": len(self.failed_tasks),
            "tasks_remaining": queue.remaining(),
            "task_statuses": dict(statuses),
        }

    def adaptive_metrics(self) -> dict[str, Any]:
        """Collect adaptive control behavior metrics."""
        controller = self.adaptive.controller
        monitor = self.adaptive.monitor
        signals = Counter(sample.signal.value for sample in monitor.signals())
        return {
            "final_state": controller.state.value,
            "aggression": self.adaptive.aggression_level().value,
            "pacing_seconds": self.adaptive.pacing_seconds(),
            "concurrency_limit": self.adaptive.concurrency_limit(),
            "backoff_seconds": self.adaptive.backoff_seconds(0),
            "is_throttling": self.adaptive.is_throttling(),
            "signal_counts": dict(signals),
            "defensive_ratio": monitor.defensive_ratio(),
            "transitions": controller.transition_history(),
        }

    def capability_matrix(self) -> list[dict[str, Any]]:
        """Build the capability-coverage matrix from the live catalog.

        For each capability: Applicable / Not Applicable / Executed / Verified
        / Blocked / Failed. ``Not Applicable`` is only ever concluded from
        discovered target characteristics (the capability was never mapped to a
        discovered surface) — never asserted by assumption.
        """
        assignments = self.surface.graph.assignments()
        tasks = self.surface.queue.tasks()
        matrix: list[dict[str, Any]] = []
        for capability_id in self.catalog:
            applicable = [a for a in assignments if a.capability_id == capability_id]
            capability_tasks = [t for t in tasks if t.capability_id == capability_id]
            executed = any(
                r["capability"] == capability_id for r in self.verdicts if r["outcome"] not in ("blocked",)
            )
            verified = any(
                r["capability"] == capability_id and r["outcome"] == AttackOutcome.SUPPORTED.value
                for r in self.verdicts
            )
            blocked = any(
                r["capability"] == capability_id and r["outcome"] == AttackOutcome.BLOCKED.value
                for r in self.verdicts
            )
            failed = any(
                r["capability"] == capability_id and r["outcome"] == AttackOutcome.ERROR.value
                for r in self.verdicts
            )
            surfaces = sorted({a.surface_key for a in applicable})
            matrix.append(
                {
                    "capability": capability_id,
                    "applicable": bool(applicable),
                    "executed": executed,
                    "verified": verified,
                    "blocked": blocked,
                    "failed": failed,
                    "queued_tasks": len(capability_tasks),
                    "not_applicable_reason": (
                        "" if applicable else "not mapped to any discovered surface characteristic"
                    ),
                    "surfaces": surfaces[:8],
                }
            )
        return matrix

    def finalize_exhaustion(self, stale_rounds: int = 4) -> dict[str, Any]:
        """Let discovery go stale and return the completion-gate proof.

        Mirrors the real runner: once the attack phase stops discovering new
        surfaces, repeated observation rounds with no new surface let the
        completion gate's discovery criterion reach exhaustion. Any
        still-actionable task (e.g. a task cap) keeps the verdict honest
        ``NOT_EXHAUSTED``.
        """
        for _ in range(stale_rounds):
            self.surface.on_observation(observation_type="probe", content={}, asset_key="", source="phase3-exhaustion")
        return self.completion_proof()

    def completion_proof(self) -> dict[str, Any]:
        """Run the completion gate and dump the queue for the exhaustion proof."""
        report = self.surface.exhaustion()
        return {
            "completion_reason": report.verdict.value,
            "machine_readable_reason": report.reason,
            "criteria": dict(report.criteria),
            "applicable_combinations": report.applicable_combinations,
            "evaluated_combinations": report.evaluated_combinations,
            "remaining_attack_tasks": sum(
                1 for task in self.surface.queue.tasks() if task.status.is_actionable
            ),
            "remaining_verification_tasks": sum(
                1
                for task in self.surface.queue.tasks()
                if task.status.is_actionable and task.verification_state.value in ("unverified", "verifying")
            ),
            "remaining_discovery_tasks": 0,
            "blocked_tasks": len(self.blocked_tasks),
            "failed_tasks": len(self.failed_tasks),
            "queue_dump": {
                task.task_id: {
                    "surface": task.surface_key,
                    "capability": task.capability_id,
                    "status": task.status.value,
                    "verification": task.verification_state.value,
                }
                for task in self.surface.queue.tasks()
            },
        }

    def report(self) -> dict[str, Any]:
        """Assemble the complete Phase 3 evidence report."""
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "generated_at": utcnow_iso(),
            "surface": self.surface_metrics(),
            "tasks": self.task_metrics(),
            "adaptive": self.adaptive_metrics(),
            "verification": {
                "probes_executed": self._probe_count,
                "verdicts": len(self.verdicts),
                "validated_findings": len(self.findings),
                "candidates": len(self.candidates),
                "findings_detail": list(self.findings),
            },
            "capability_matrix": self.capability_matrix(),
            "completion": self.completion_proof(),
            "blocked_tasks": list(self.blocked_tasks),
            "failed_tasks": list(self.failed_tasks),
        }


def _max_status(responses: list[dict[str, Any]]) -> int | None:
    """Return the most defensive HTTP status observed (or ``None``)."""
    statuses = [int(r.get("status") or 0) for r in responses if isinstance(r, dict)]
    for status in (429, 403):
        if status in statuses:
            return status
    return max((s for s in statuses if s >= 500), default=None)


def _total_ms(responses: list[dict[str, Any]]) -> int:
    """Return the total elapsed milliseconds across responses."""
    return sum(int(r.get("elapsed_ms") or 0) for r in responses if isinstance(r, dict))


__all__ = ["Phase3Harness"]
