# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission telemetry engine.

Sprint 032. Tracks decision latency, tool utilization, finding yield,
validation yield, false-positive rate, coverage, evidence quality, branch
efficiency, resource utilization, failed actions and fallback rate. Telemetry
is a JSON-safe snapshot produced at checkpoint/finalize time.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.domain.mission_orchestration.models import TelemetrySnapshot
from hunterx.shared.time import utcnow_iso


class MissionTelemetry:
    """Record and compute mission telemetry snapshots."""

    def snapshot(self, mission: OrchestratedMission) -> TelemetrySnapshot:
        """Compute the current telemetry snapshot for a mission."""
        decisions = mission.decisions
        decision_latency = (
            sum(decision.latency_ms for decision in decisions) / len(decisions)
            if decisions
            else 0.0
        )
        executions = mission.budget.executions_used
        tool_utilization = min(1.0, executions / max(1, mission.budget.executions_budget))

        findings = mission.context.findings
        validated = sum(1 for finding in findings if finding.get("stage") in ("verified", "proven", "report_ready"))
        candidates = max(1, len(findings))
        finding_yield = round(validated / candidates, 4)
        validation_yield = round(validated / max(1, executions), 4) if executions else 0.0

        false_positive_rate = self._false_positive_rate(mission)

        coverage_ratio = mission.coverage_ratio()
        evidence_quality = self._evidence_quality(mission)
        branch_efficiency = self._branch_efficiency(mission)
        failed = sum(
            1
            for entry in mission.context.history
            if "fail" in str(entry.get("event", "")).lower() or entry.get("outcome") == "failed"
        )
        fallback_rate = self._fallback_rate(mission)
        resource_utilization = round(
            (mission.budget.cpu_percent / 100.0 + mission.budget.memory_mb / 1024.0 + tool_utilization) / 3.0,
            4,
        )

        ai = self._ai_telemetry(mission)

        return TelemetrySnapshot(
            mission_id=mission.mission_id,
            decision_count=len(decisions),
            decision_latency_ms_avg=round(decision_latency, 2),
            tool_executions=executions,
            tool_utilization=round(tool_utilization, 4),
            finding_yield=finding_yield,
            validation_yield=validation_yield,
            false_positive_rate=false_positive_rate,
            coverage_ratio=coverage_ratio,
            evidence_quality=evidence_quality,
            branch_efficiency=branch_efficiency,
            failed_actions=failed,
            fallback_rate=fallback_rate,
            resource_utilization=resource_utilization,
            ai_enabled=ai["enabled"],
            ai_provider=ai["provider"],
            ai_model=ai["model"],
            ai_requests_attempted=ai["attempted"],
            ai_requests_succeeded=ai["succeeded"],
            ai_requests_failed=ai["failed"],
            ai_http_429=ai["http_429"],
            ai_timeouts=ai["timeouts"],
            ai_provider_errors=ai["provider_errors"],
            ai_fallbacks=ai["fallbacks"],
            ai_assisted_decisions=ai["assisted_decisions"],
            recorded_at=utcnow_iso(),
        )

    def record(self, mission: OrchestratedMission) -> TelemetrySnapshot:
        """Compute and append a telemetry snapshot to the mission."""
        snapshot = self.snapshot(mission)
        mission.telemetry_snapshots.append(snapshot)
        return snapshot

    @staticmethod
    def _false_positive_rate(mission: OrchestratedMission) -> float:
        """Estimate the false-positive rate from refuted/disproved hypotheses."""
        terminal = [
            hypothesis
            for hypothesis in mission.hypotheses
            if hypothesis.state.value in ("refuted", "disproved", "validated")
        ]
        if not terminal:
            return 0.0
        negatives = sum(1 for hypothesis in terminal if hypothesis.state.value in ("refuted", "disproved"))
        return round(negatives / len(terminal), 4)

    @staticmethod
    def _evidence_quality(mission: OrchestratedMission) -> float:
        """Return the average evidence confidence across observations."""
        observations = mission.observations
        if not observations:
            return 0.0
        return round(sum(observation.confidence for observation in observations) / len(observations), 4)

    @staticmethod
    def _branch_efficiency(mission: OrchestratedMission) -> float:
        """Return the fraction of resolved branches with a positive outcome."""
        resolved = [branch for branch in mission.branches if branch.state == "resolved"]
        if not resolved:
            return 0.0
        positive = sum(1 for branch in resolved if branch.outcome in ("validated", "confirmed"))
        return round(positive / len(resolved), 4)

    @staticmethod
    def _fallback_rate(mission: OrchestratedMission) -> float:
        """Return the fallback rate across executed actions."""
        executed = mission.budget.executions_used
        if executed == 0:
            return 0.0
        fallbacks = len(mission.mission.fallbacks)
        return round(fallbacks / executed, 4)

    @staticmethod
    def _ai_telemetry(mission: OrchestratedMission) -> dict[str, object]:
        """Aggregate AI-invocation telemetry from the reasoning-trace entries.

        Every ``ai_invoked`` trace entry records the provider round-trip
        (provider/model, latency, success/failure, HTTP status when available,
        fallback flag). Counters are aggregated across the mission and are
        always derived from trace facts — never guessed.
        """
        attempted = succeeded = failed = http_429 = timeouts = provider_errors = 0
        fallbacks = 0
        provider = ""
        model = ""
        enabled = False
        for entry in mission.trace:
            content = dict(entry.content or {})
            if not content.get("ai_invoked"):
                continue
            enabled = True
            provider = str(content.get("ai_provider") or provider)
            model = str(content.get("ai_model") or model)
            attempted += 1
            status = content.get("ai_http_status")
            error = str(content.get("ai_error") or "")
            if content.get("ai_usable"):
                succeeded += 1
            else:
                failed += 1
                if status == 429:
                    http_429 += 1
                elif content.get("ai_timeout"):
                    timeouts += 1
                elif error:
                    provider_errors += 1
            if content.get("ai_fallback"):
                fallbacks += 1
        assisted = sum(1 for decision in mission.decisions if bool(decision.ai_assisted))
        return {
            "enabled": enabled,
            "provider": provider,
            "model": model,
            "attempted": attempted,
            "succeeded": succeeded,
            "failed": failed,
            "http_429": http_429,
            "timeouts": timeouts,
            "provider_errors": provider_errors,
            "fallbacks": fallbacks,
            "assisted_decisions": assisted,
        }


__all__ = ["MissionTelemetry"]
