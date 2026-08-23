# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous model-driven attacker (Phase 7).

The attacker closes the loop the connected model participates in:

    reason → accept → schedule real task → execute real engine →
    observe → verify → learn → reason again

Every accepted model hypothesis becomes a real attack-surface assessment task
that runs through the ordinary capability execution engine — the same queue as
every discovery-derived task. Attack results and validated findings are fed
back into the model's reasoning context, and a finding never terminates the
loop: it expands the search (adjacent parameters, sibling endpoints,
alternative vectors). The loop only reports genuine exhaustion when the queue
is drained, no hypothesis is pending, no model-generated task remains, and the
model produced no further attack path — anything else (budgets, cycles, an
unavailable model) is reported truthfully as a resource limit, never as
completion.
"""

from __future__ import annotations

import contextlib
from dataclasses import replace
from typing import Any

from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.domain.attack_surface.enums import SurfaceLayer
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_finding.models import CapabilityCandidate
from hunterx.domain.model_attacker.dedup import hypothesis_fingerprint
from hunterx.domain.model_attacker.enums import AttackerCompletion, ModelHypothesisStatus
from hunterx.domain.model_attacker.learning import LearningContext, adjacent_paths_for
from hunterx.domain.model_attacker.models import AttackPlan, ModelFeedbackEvent, ModelHypothesis
from hunterx.domain.model_attacker.reasoner import ModelReasoner
from hunterx.domain.model_attacker.telemetry import AttackerTelemetry
from hunterx.shared.time import utcnow_iso


class ModelAttacker:
    """Drive the connected model through the real attack loop for one mission.

    Args:
        reasoner: the model-agnostic reasoner (``None`` keeps the attacker
            inert — no model, no hypotheses, genuine no-op).
        finding_pipeline: the Phase 6 capability-finding pipeline that turns
            capability-execution FINDING records into validated findings.
        max_hypotheses_per_cycle: bounded hypotheses accepted per reasoning
            round (a resource ceiling, never a completion signal).
        max_cycles: bounded reasoning rounds (a resource ceiling).

    """

    def __init__(
        self,
        reasoner: ModelReasoner | None = None,
        *,
        finding_pipeline: Any | None = None,
        max_hypotheses_per_cycle: int = 8,
        max_cycles: int = 24,
        max_context_observations: int = 60,
        max_context_findings: int = 20,
        max_context_paths: int = 30,
        max_context_disproven: int = 200,
        max_context_surfaces: int = 100,
    ) -> None:
        self._reasoner = reasoner or ModelReasoner()
        self._pipeline = finding_pipeline
        self._max_hypotheses = max(1, max_hypotheses_per_cycle)
        self._max_cycles = max(1, max_cycles)
        #: Bounded reasoning context: the model must receive an efficient
        #: summarized state, never an ever-growing full mission history.
        self._max_context_surfaces = max(1, max_context_surfaces)

        self._mission_id = ""
        self._surface = None
        self._session = None
        self._adaptive = None
        self._engine: CapabilityExecutionEngine | None = None

        self._hypotheses: dict[str, ModelHypothesis] = {}
        self._plans: list[AttackPlan] = []
        self._dedup: dict[str, str] = {}
        self._processed_records: set[tuple[str, str, str, str]] = set()
        self._last_rejections: list[dict[str, Any]] = []
        self._learning = LearningContext(
            max_observations=max_context_observations,
            max_findings=max_context_findings,
            max_paths=max_context_paths,
            max_disproven=max_context_disproven,
        )
        self._telemetry = AttackerTelemetry()
        self._bound = False
        self._completion_reason: str = ""
        self._found_finding = False
        self._cycles_run = 0
        self._last_reason: str = ""

    # -- binding -------------------------------------------------------------

    def bind(
        self,
        surface: Any,
        *,
        mission_id: str = "",
        session: Any | None = None,
        adaptive: Any | None = None,
    ) -> None:
        """Bind the attacker to a per-mission surface and session."""
        self._mission_id = mission_id or str(getattr(surface, "mission_id", "") or "")
        self._surface = surface
        self._session = session
        self._adaptive = adaptive
        self._engine = CapabilityExecutionEngine(
            mission_id=self._mission_id or "model-attacker",
            target_key=str(getattr(surface, "target_key", "") or ""),
            surface=surface,
            adaptive=adaptive,
        )
        self._bound = True

    # -- loop ----------------------------------------------------------------

    def step(self) -> dict[str, Any]:
        """Run one closed-loop round; return a JSON-safe step summary."""
        if not self._bound or self._surface is None or self._engine is None:
            return {"status": "idle", "pending": False, "reason": "not bound"}
        if self._cycles_run >= self._max_cycles:
            self._completion_reason = AttackerCompletion.RESOURCE_LIMIT.value
            self._refresh_counts()
            return {
                "status": "resource_limit",
                "pending": self.has_pending(),
                "reason": "model attack cycle ceiling reached",
                "completion_reason": self._completion_reason,
            }
        self._cycles_run += 1
        self._telemetry.cycles = self._cycles_run

        result = self._reasoner.reason(self._context())
        self._telemetry.model_calls += 1
        if self._found_finding and result.invoked:
            self._telemetry.post_finding_model_calls += 1
        self._last_reason = "empty" if result.invoked and not result.usable and result.failure_reason.value == "none" else "used"

        if result.error and not result.usable:
            self._telemetry.model_failures += 1
            self._telemetry.model_failure_reason = result.error
            self._completion_reason = AttackerCompletion.MODEL_UNAVAILABLE.value
            self._refresh_counts()
            return {
                "status": "model_unavailable",
                "pending": self.has_pending(),
                "reason": result.error,
                "completion_reason": self._completion_reason,
            }

        accepted = self._accept(result.hypotheses)
        self._telemetry.hypotheses_generated += len(result.hypotheses) + len(result.rejected)
        self._telemetry.hypotheses_rejected += len(result.rejected) + len(self._last_rejections)

        executed = self._execute_pending()
        self._telemetry.model_task_execution_count += executed
        self._telemetry.model_generated_tasks = sum(1 for plan in self._plans if plan.task_id)

        observations = self._observe()
        self._telemetry.model_feedback_events += len(observations)

        self._refresh_counts()
        self._exhaustion_report = self._exhaustion_snapshot()
        exhausted = self._exhaustion_report.get("exhausted", False)
        if exhausted:
            self._completion_reason = AttackerCompletion.EXHAUSTED.value
        return {
            "status": "exhausted" if exhausted else "active",
            "pending": self.has_pending(),
            "accepted": len(accepted),
            "rejected": len(self._last_rejections),
            "tasks_executed": executed,
            "observations": len(observations),
            "hypotheses": [hypothesis.to_dict() for hypothesis in accepted],
            "completion_reason": self._completion_reason,
        }

    def run(self, *, max_rounds: int = 0) -> dict[str, Any]:
        """Loop ``step()`` until exhaustion or a resource ceiling."""
        limit = max_rounds or self._max_cycles
        steps: list[dict[str, Any]] = []
        for _ in range(limit):
            step = self.step()
            steps.append(step)
            if not step.get("pending", True):
                break
        if not self.exhausted() and not self._completion_reason:
            # A bounded-round ceiling hit without genuine exhaustion is a
            # resource limit — never a completion signal.
            self._completion_reason = AttackerCompletion.RESOURCE_LIMIT.value
        return {"steps": steps, **self.report()}

    # -- state ---------------------------------------------------------------

    def exhausted(self) -> bool:
        """Return ``True`` when the attack loop is genuinely exhausted.

        Exhaustion requires the queue drained, no pending hypothesis, no
        pending model-generated task and the model's latest reasoning round
        producing no further attack path.
        """
        if not self._bound:
            return True
        return bool(self._exhaustion_snapshot().get("exhausted", False))

    def has_pending(self) -> bool:
        """Return ``True`` while real model work may still be outstanding.

        The loop stays alive until genuine exhaustion is reached: even after a
        fully drained round, the connected model may produce further attack
        paths on the next reasoning round, so the attacker only reports no
        pending work once it is genuinely exhausted.
        """
        if not self._bound:
            return False
        return not self.exhausted()

    def completion_reason(self) -> str:
        """Return the truthful completion reason (never fabricated)."""
        if self._completion_reason:
            return self._completion_reason
        return AttackerCompletion.STOPPED.value

    def model_unavailable(self) -> bool:
        """Return ``True`` when the model is unavailable/rate-limited.

        True when the latest reasoning round failed with a provider failure
        (e.g. OpenRouter 429) and set the attacker's completion reason to
        MODEL_UNAVAILABLE. Used by the mission runner to classify an
        un-dispatched attacker as AI_UNAVAILABLE (never resource exhaustion).
        """
        return self._completion_reason == AttackerCompletion.MODEL_UNAVAILABLE.value

    def telemetry(self) -> dict[str, Any]:
        """Return the machine-readable mission telemetry."""
        self._refresh_counts()
        return self._telemetry.to_dict()

    def report(self) -> dict[str, Any]:
        """Return the machine-readable autonomous-loop report."""
        self._refresh_counts()
        return {
            "mission_id": self._mission_id,
            "telemetry": self._telemetry.to_dict(),
            "hypotheses": [hypothesis.to_dict() for hypothesis in self._hypotheses.values()],
            "plans": [plan.to_dict() for plan in self._plans],
            "learning": self._learning.summary(),
            "exhaustion": self._exhaustion_snapshot(),
            "completion_reason": self.completion_reason(),
        }

    # -- internals -----------------------------------------------------------

    def _context(self) -> dict[str, Any]:
        learning = self._learning.summary()
        return {
            "target": str(getattr(self._surface, "target_key", "") or ""),
            "session_state": str(getattr(self._session, "state", "") or "anonymous") if self._session is not None else "anonymous",
            "surfaces": self._surfaces(),
            "catalog": sorted(self._catalog_ids()),
            "observations": learning["observations"],
            "findings": learning["validated_findings"],
            "adjacent_paths": learning["adjacent_paths"],
            "disproven": learning["disproven_hypotheses"],
        }

    def _surfaces(self) -> list[dict[str, Any]]:
        if self._surface is None:
            return []
        graph = self._surface.graph
        surfaces: dict[str, list[str]] = {}
        for node in graph.nodes():
            if node.layer is SurfaceLayer.SURFACE:
                surfaces.setdefault(node.name, [])
            elif node.layer is SurfaceLayer.INPUT:
                parent = graph.parent(node.key)
                endpoint = parent.name if parent is not None else ""
                if node.name not in surfaces.setdefault(endpoint, []):
                    surfaces[endpoint].append(node.name)
        # Bounded context: only the most recently discovered surfaces are fed to
        # the model (older surfaces remain on the mission/surface state, they are
        # just excluded from the prompt summary).
        bounded = [
            {"surface": endpoint, "parameters": parameters, "layer": "surface"}
            for endpoint, parameters in surfaces.items()
        ][-self._max_context_surfaces :]
        return bounded

    @staticmethod
    def _catalog_ids() -> set[str]:
        from hunterx.domain.vulnerability_capability.registry import capabilities

        return {capability.vulnerability_class for capability in capabilities()}

    def _accept(self, hypotheses: tuple[ModelHypothesis, ...]) -> list[ModelHypothesis]:
        accepted: list[ModelHypothesis] = []
        self._last_rejections = []
        for hypothesis in hypotheses[: self._max_hypotheses]:
            fingerprint = hypothesis_fingerprint(
                capability=hypothesis.capability,
                surface=hypothesis.surface,
                attack_vector=hypothesis.attack_vector,
                attack_strategy=hypothesis.attack_strategy,
                authentication_context=hypothesis.authentication_context,
                workflow_context=hypothesis.workflow_context,
                parent_hypothesis=hypothesis.parent_hypothesis,
            )
            if fingerprint in self._dedup or fingerprint in self._learning.disproven_fingerprints:
                self._last_rejections.append({"capability": hypothesis.capability, "surface": hypothesis.surface, "reason": "duplicate or disproven"})
                continue
            hypothesis = replace(
                hypothesis,
                fingerprint=fingerprint,
                status=ModelHypothesisStatus.ACCEPTED,
            )
            self._hypotheses[hypothesis.hypothesis_id] = hypothesis
            self._dedup[fingerprint] = hypothesis.hypothesis_id
            plan = self._plan_for(hypothesis)
            self._plans.append(plan)
            if plan.task_id:
                self._telemetry.hypotheses_accepted += 1
                accepted.append(hypothesis)
        return accepted

    def _plan_for(self, hypothesis: ModelHypothesis) -> AttackPlan:
        if self._surface is None:
            return AttackPlan(
                hypothesis_id=hypothesis.hypothesis_id,
                capability=hypothesis.capability,
                surface=hypothesis.surface,
                vector=hypothesis.attack_vector,
                strategy=hypothesis.attack_strategy,
            )
        task_id, covered = self._schedule(hypothesis)
        status = ModelHypothesisStatus.QUEUED if task_id else ModelHypothesisStatus.REJECTED
        self._hypotheses[hypothesis.hypothesis_id] = self._hypotheses[hypothesis.hypothesis_id].with_status(status)
        if not task_id:
            self._last_rejections.append(
                {
                    "capability": hypothesis.capability,
                    "surface": hypothesis.surface,
                    "attack_vector": hypothesis.attack_vector,
                    "reason": "already assessed by a prior task" if covered else "capability not applicable to the surface (no assessment task produced)",
                }
            )
        return AttackPlan(
            hypothesis_id=hypothesis.hypothesis_id,
            capability=hypothesis.capability,
            surface=hypothesis.surface,
            vector=hypothesis.attack_vector,
            strategy=hypothesis.attack_strategy,
            task_id=task_id or "",
            queued_at=utcnow_iso() if task_id else "",
        )

    def _schedule(self, hypothesis: ModelHypothesis) -> tuple[str, bool]:
        """Schedule a real assessment task for the hypothesis.

        Returns ``(task_id, covered)`` where ``covered`` marks an already
        assessed (settled) task so the hypothesis is rejected honestly rather
        than left queued forever.
        """
        if self._surface is None:
            return "", False
        with contextlib.suppress(Exception):  # scheduling must never break the loop
            self._surface.on_observation(
                observation_type="parameter",
                content={"parameters": [hypothesis.attack_vector]},
                asset_key=hypothesis.surface,
                session_state=hypothesis.authentication_context,
                source="model_attacker",
            )
            node = self._find_input_node(hypothesis.surface, hypothesis.attack_vector)
            if node is None:
                return "", False
            task = next(
                (
                    candidate
                    for candidate in self._surface.queue.tasks()
                    if candidate.capability_id == hypothesis.capability and candidate.surface_key == node.key
                ),
                None,
            )
            if task is None:
                return "", False
            if not task.status.is_actionable:
                return "", True
            return task.task_id, False
        return "", False

    def _find_input_node(self, surface: str, vector: str) -> Any:
        if self._surface is None:
            return None
        graph = self._surface.graph
        for node in graph.nodes():
            if node.layer is not SurfaceLayer.INPUT or node.name != vector:
                continue
            parent = graph.parent(node.key)
            if parent is not None and parent.name == surface:
                return node
        return None

    def _execute_pending(self) -> int:
        if self._engine is None:
            return 0
        before = len(self._engine.records)
        with contextlib.suppress(Exception):  # execution failures are recorded, never fatal
            self._engine.execute_ready(session=self._session)
        return len(self._engine.records) - before

    def _observe(self) -> list[dict[str, Any]]:
        if self._engine is None:
            return []
        events: list[dict[str, Any]] = []
        new_records = [record for record in self._engine.records if self._record_key(record) not in self._processed_records]
        for record in new_records:
            self._processed_records.add(self._record_key(record))
            supported = record.outcome is CapabilityExecutionStatus.FINDING
            contradicted = record.outcome in (CapabilityExecutionStatus.NO_FINDING, CapabilityExecutionStatus.VERIFIED)
            signal = str((record.evidence or {}).get("signal") or record.reason or "")
            self._learning.record_observation(
                hypothesis_id="",
                capability=record.capability_id,
                surface=record.endpoint,
                signal=signal,
                supported=supported,
            )
            events.append(
                ModelFeedbackEvent(
                    hypothesis_id="",
                    capability=record.capability_id,
                    surface=record.endpoint,
                    signal=signal,
                    supported=supported,
                    contradicted=contradicted,
                    finding=record.outcome is CapabilityExecutionStatus.FINDING,
                ).to_dict()
            )
            self._mark_hypothesis_executed(record)
            if contradicted:
                self._remember_contradiction(record)
            if record.outcome is CapabilityExecutionStatus.FINDING:
                self._materialize_finding(record)
        return events

    def _materialize_finding(self, record: Any) -> None:
        self._found_finding = True
        self._telemetry.finding_events += 1
        if self._pipeline is None:
            return
        try:
            candidate = CapabilityCandidate.from_capability_record(record)
            outcome = self._pipeline.run(candidate)
        except Exception:  # noqa: BLE001 - finding materialization is best-effort in the loop
            return
        if outcome.get("verdict") == "report_ready":
            self._telemetry.validated_findings += 1
            finding = {
                "vulnerability_class": outcome.get("finding_class") or "",
                "capability": outcome.get("finding_class") or "",
                "surface": outcome.get("endpoint") or "",
                "vector": outcome.get("vector") or "",
                "severity": outcome.get("severity") or "",
                "finding_id": outcome.get("finding_id") or "",
                "evidence": (outcome.get("package") or {}).get("evidence") or [],
                "model_calls_at_validation": self._telemetry.model_calls,
                "hypotheses_at_validation": self._telemetry.hypotheses_accepted,
                "tasks_at_validation": self._telemetry.model_task_execution_count,
            }
            related = adjacent_paths_for(finding, self._surfaces())
            self._learning.record_finding(finding, related=related)
            self._telemetry.new_attack_paths += len(related)

    def _mark_hypothesis_executed(self, record: Any) -> None:
        """Advance a matching hypothesis past QUEUED once its task executed."""
        if record.outcome in (CapabilityExecutionStatus.NO_FINDING, CapabilityExecutionStatus.VERIFIED):
            return  # contradiction handling sets DISPROVED
        for hypothesis_id, hypothesis in list(self._hypotheses.items()):
            if (
                hypothesis.capability != record.capability_id
                or hypothesis.surface != record.endpoint
                or hypothesis.attack_vector != record.vector
            ):
                continue
            status = (
                ModelHypothesisStatus.VALIDATED
                if record.outcome is CapabilityExecutionStatus.FINDING
                else ModelHypothesisStatus.EXECUTED
            )
            self._hypotheses[hypothesis_id] = hypothesis.with_status(status)
            return

    def _remember_contradiction(self, record: Any) -> None:
        for hypothesis in self._hypotheses.values():
            if (
                hypothesis.capability == record.capability_id
                and hypothesis.surface == record.endpoint
                and hypothesis.attack_vector == record.vector
            ):
                self._learning.remember_disproven(hypothesis.fingerprint)
                self._hypotheses[hypothesis.hypothesis_id] = hypothesis.with_status(ModelHypothesisStatus.DISPROVED)
                return

    @staticmethod
    def _record_key(record: Any) -> tuple[str, str, str, str]:
        return (record.capability_id, record.surface_key, record.endpoint, record.recorded_at)

    def _pending_hypotheses(self) -> int:
        return sum(
            1
            for hypothesis in self._hypotheses.values()
            if hypothesis.status in (ModelHypothesisStatus.PROPOSED, ModelHypothesisStatus.ACCEPTED, ModelHypothesisStatus.QUEUED)
        )

    def _pending_model_tasks(self) -> int:
        if self._surface is None:
            return 0
        count = 0
        for plan in self._plans:
            if not plan.task_id:
                continue
            task = self._surface.queue.get(plan.task_id)
            if task is not None and task.status.is_actionable:
                count += 1
        return count

    def _queue_remaining(self) -> int:
        return self._surface.queue.remaining() if self._surface is not None else 0

    def _refresh_counts(self) -> None:
        self._telemetry.remaining_hypotheses = self._pending_hypotheses()
        self._telemetry.remaining_attack_tasks = self._pending_model_tasks()
        self._telemetry.completion_reason = self._completion_reason

    def _exhaustion_snapshot(self) -> dict[str, Any]:
        if self._surface is None:
            return {"exhausted": False, "reason": "not bound"}
        gate = self._surface.gate.evaluate(self._surface.graph, self._surface.queue)
        queue_drained = self._surface.queue.exhausted()
        no_hypotheses = self._pending_hypotheses() == 0
        no_model_tasks = self._pending_model_tasks() == 0
        no_new_paths = self._last_reason == "empty"
        exhausted = queue_drained and no_hypotheses and no_model_tasks and no_new_paths
        return {
            "exhausted": exhausted,
            "queue_drained": queue_drained,
            "pending_hypotheses": self._pending_hypotheses(),
            "pending_model_tasks": self._pending_model_tasks(),
            "model_produced_new_paths": no_new_paths is False,
            "gate_verdict": gate.verdict.value,
            "reason": "genuine exhaustion" if exhausted else "work remains",
        }


__all__ = ["ModelAttacker"]
