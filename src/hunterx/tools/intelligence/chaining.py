# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool chain executor (Sprint 034.5).

Executes a planned :class:`ToolChain` end-to-end through the Tool Integration
SDK: steps run in dependency order, each step's raw output is preserved, parsed
output is projected into canonical observations with full provenance (source
tool, execution id, mission id, target id, timestamp, raw artifact reference,
confidence), discovered hosts/URLs feed dependent steps, and failures are
classified with a capability-equivalent fallback attempt while partial results
are preserved.

A chain result never invents evidence: a step that produced no observation is
recorded as such, and a failed step never becomes "target is safe".
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    ChainStatus,
    ChainStepResult,
    ChainStepState,
    ToolChain,
    ToolChainResult,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine

#: JSON payload keys that carry parsed records per tool family.
_RECORD_KEYS: tuple[str, ...] = (
    "discoveries",
    "dns_records",
    "urls",
    "requests",
    "candidates",
    "observations",
    "findings",
    "vulnerabilities",
    "secrets",
    "apis",
    "parameters",
    "references",
    "datasets",
    "content",
)

#: Capability → canonical observation kind used for record projection.
_CAPABILITY_KIND: dict[str, str] = {
    "subdomain-discovery": "domain",
    "subdomain-enumeration": "domain",
    "domain-enumeration": "domain",
    "dns-enumeration": "domain",
    "dns-records": "domain",
    "dns-resolution": "domain",
    "host-discovery": "ip",
    "port-scanning": "port",
    "port-discovery": "port",
    "service-fingerprint": "service",
    "service-discovery": "service",
    "os-detection": "service",
    "http-probing": "url",
    "http-enumeration": "url",
    "web-crawling": "url",
    "crawling": "url",
    "directory-discovery": "path",
    "file-enumeration": "path",
    "parameter-discovery": "parameter",
    "javascript-analysis": "path",
    "javascript-discovery": "path",
    "endpoint-discovery": "path",
    "endpoint-extraction": "path",
    "api-discovery": "path",
    "graphql-testing": "parameter",
    "graphql-analysis": "parameter",
    "graphql-introspection": "parameter",
    "technology-detection": "technology",
    "waf-detection": "technology",
    "vulnerability-scan": "vulnerability",
    "web-vulnerability-detection": "vulnerability",
    "sqli-detection": "vulnerability",
    "sql-injection-detection": "vulnerability",
    "xss-detection": "vulnerability",
    "ssti-detection": "vulnerability",
    "command-injection": "vulnerability",
    "xxe-detection": "vulnerability",
    "secrets-detection": "other",
    "secrets-scan": "other",
    "secret-discovery": "other",
    "static-analysis": "other",
    "sast": "other",
    "cloud-assessment": "cloud-resource",
    "cloud-misconfiguration": "cloud-resource",
    "image-scan": "vulnerability",
    "container-analysis": "cloud-resource",
}

#: Record fields that act as the observation value, in priority order.
_VALUE_FIELDS: tuple[str, ...] = (
    "name",
    "host",
    "url",
    "value",
    "domain",
    "ip",
    "subdomain",
    "path",
    "parameter",
    "endpoint",
    "location",
    "secret_type",
    "template_id",
    "title",
    "matched_at",
)


class ChainExecutor:
    """Execute a :class:`ToolChain` end-to-end through the SDK.

    Usage::

        executor = ChainExecutor(engine, tip=tip)
        result = executor.execute(chain, target="example.com", mission_id="m1")
    """

    def __init__(
        self,
        engine: ExecutionEngine,
        tip: ToolIntelligenceAPI | None = None,
        *,
        event_bus: Any = None,
    ) -> None:
        self._engine = engine
        self._tip = tip
        self._event_bus = event_bus

    # -- public API ---------------------------------------------------------

    def execute(
        self,
        chain: ToolChain,
        *,
        target: str,
        target_type: str = "",
        mission_id: str = "",
        scope: str = "",
        parameters: dict[str, Any] | None = None,
        correlation_id: str = "",
        timeout: float = 0.0,
        allow_fallback: bool = True,
    ) -> ToolChainResult:
        """Run ``chain`` against ``target`` and return the chain outcome.

        Steps run in dependency order. Failures are classified; when
        ``allow_fallback`` is set a capability-equivalent tool with a
        registered adapter is attempted once. Partial results are always
        preserved in the returned step results.
        """
        correlation_id = correlation_id or generate_id()
        order = self._order(chain)
        step_results: list[ChainStepResult] = []
        derived: dict[str, list[str]] = {}
        observations: list[CanonicalObservation] = []
        failed: list[str] = []
        completed: list[str] = []

        for step in order:
            prerequisites_ok = all(
                dep in completed for dep in chain.dependencies.get(step.step_id, ())
            )
            if not prerequisites_ok:
                step_results.append(
                    ChainStepResult(
                        step_id=step.step_id,
                        tool_id=step.tool_id,
                        status=ChainStepState.SKIPPED,
                        error="prerequisite step did not complete",
                    )
                )
                continue

            outcome = self._run_step(
                step,
                chain=chain,
                target=target,
                target_type=target_type,
                mission_id=mission_id,
                scope=scope,
                parameters=parameters,
                correlation_id=correlation_id,
                timeout=timeout or step.timeout,
                allow_fallback=allow_fallback,
                derived=derived,
            )
            step_results.append(outcome)
            observations.extend(outcome.observations)
            if outcome.status is ChainStepState.COMPLETED:
                completed.append(step.step_id)
            elif outcome.status is ChainStepState.FAILED:
                failed.append(step.step_id)
            derived[step.step_id] = _derived_targets(list(outcome.observations))

        return ToolChainResult(
            chain_id=chain.chain_id,
            status=_chain_status(chain, completed, failed),
            step_results=tuple(step_results),
            completed_steps=tuple(completed),
            failed_steps=tuple(failed),
            skipped_steps=tuple(
                result.step_id for result in step_results if result.status is ChainStepState.SKIPPED
            ),
        )

    # -- internals ----------------------------------------------------------

    def _order(self, chain: ToolChain) -> list[Any]:
        """Return steps in dependency (topological) order."""
        pending = {step.step_id: list(chain.dependencies.get(step.step_id, ())) for step in chain.steps}
        by_id = {step.step_id: step for step in chain.steps}
        ordered: list[Any] = []
        while pending:
            ready = [step_id for step_id, deps in pending.items() if not deps]
            if not ready:
                # Cycle or missing prerequisite: run remaining steps in declared order.
                for step_id in list(pending):
                    ordered.append(by_id[step_id])
                pending.clear()
                break
            ready.sort()
            for step_id in ready:
                ordered.append(by_id[step_id])
                pending.pop(step_id)
                for remaining in pending:
                    if step_id in pending[remaining]:
                        pending[remaining].remove(step_id)
        return ordered

    def _run_step(
        self,
        step: Any,
        *,
        chain: ToolChain,
        target: str,
        target_type: str,
        mission_id: str,
        scope: str,
        parameters: dict[str, Any] | None,
        correlation_id: str,
        timeout: float,
        allow_fallback: bool,
        derived: dict[str, list[str]],
    ) -> ChainStepResult:
        step_target = self._step_target(step, target, derived)

        # Steps whose tool has no registered adapter are skipped (never faked).
        if self._engine.adapter_for(step.tool_id) is None:
            if allow_fallback:
                fallback_tool = self._select_fallback(step, step.tool_id)
                if fallback_tool:
                    return self._run_tool(
                        step,
                        tool_id=fallback_tool,
                        fallback=True,
                        target=step_target,
                        target_type=target_type,
                        mission_id=mission_id,
                        scope=scope,
                        parameters=parameters,
                        correlation_id=correlation_id,
                        timeout=timeout,
                        original_error=f"primary tool '{step.tool_id}' has no registered adapter",
                    )
            return ChainStepResult(
                step_id=step.step_id,
                tool_id=step.tool_id,
                status=ChainStepState.SKIPPED,
                error=f"tool '{step.tool_id}' has no registered adapter",
            )

        return self._run_tool(
            step,
            tool_id=step.tool_id,
            fallback=False,
            target=step_target,
            target_type=target_type,
            mission_id=mission_id,
            scope=scope,
            parameters=parameters,
            correlation_id=correlation_id,
            timeout=timeout,
            allow_fallback=allow_fallback,
            original_error="",
        )

    def _run_tool(
        self,
        step: Any,
        *,
        tool_id: str,
        fallback: bool,
        target: str,
        target_type: str,
        mission_id: str,
        scope: str,
        parameters: dict[str, Any] | None,
        correlation_id: str,
        timeout: float,
        allow_fallback: bool = True,
        original_error: str = "",
    ) -> ChainStepResult:
        context = self._build_context(
            step=step,
            tool_id=tool_id,
            target=target,
            target_type=target_type,
            mission_id=mission_id,
            scope=scope,
            parameters=parameters,
            correlation_id=correlation_id,
            timeout=timeout,
        )
        result = self._engine.execute(context)
        if result.result.ok:
            return self._success_step(step, context, result.result, fallback=fallback, original_error=original_error)
        error = result.result.error or (
            result.result.failure_kind.value if result.result.failure_kind is not None else "failed"
        )
        if fallback or not allow_fallback:
            return ChainStepResult(
                step_id=step.step_id,
                tool_id=context.tool_id,
                status=ChainStepState.FAILED,
                error=error,
            )
        # Attempt a capability-equivalent fallback once on failure.
        fallback_tool = self._select_fallback(step, context.tool_id)
        if fallback_tool:
            return self._run_tool(
                step,
                tool_id=fallback_tool,
                fallback=True,
                target=target,
                target_type=target_type,
                mission_id=mission_id,
                scope=scope,
                parameters=parameters,
                correlation_id=correlation_id,
                timeout=timeout,
                allow_fallback=False,
                original_error=error,
            )
        return ChainStepResult(
            step_id=step.step_id,
            tool_id=context.tool_id,
            status=ChainStepState.FAILED,
            error=error,
        )

    def _success_step(
        self,
        step: Any,
        context: Any,
        result: Any,
        *,
        fallback: bool,
        original_error: str,
    ) -> ChainStepResult:
        observations = self._extract_observations(step, context, result)
        return ChainStepResult(
            step_id=step.step_id,
            tool_id=context.tool_id,
            status=ChainStepState.COMPLETED,
            execution=_execution_record(context, result),
            observations=tuple(observations),
            error=original_error,
        )

    def _build_context(
        self,
        *,
        step: Any,
        tool_id: str,
        target: str,
        target_type: str,
        mission_id: str,
        scope: str,
        parameters: dict[str, Any] | None,
        correlation_id: str,
        timeout: float,
    ) -> Any:
        from hunterx.domain.execution import ExecutionContext

        step_params = dict(step.inputs or {})
        if parameters:
            merged = dict(parameters)
            merged.update(step_params)
            step_params = merged
        return ExecutionContext(
            tool_id=tool_id,
            mission_id=mission_id,
            target=target,
            target_type=target_type or "",
            profile="",
            correlation_id=correlation_id,
            timeout_seconds=timeout,
            permissions=self._permissions_for(tool_id),
            parameters=step_params,
        )

    def _permissions_for(self, tool_id: str) -> tuple[str, ...]:
        """Return the permissions the tool's adapter requires.

        The sandbox denies executions whose context does not explicitly grant
        the adapter-requested permission flags. Mirroring the mission
        executor, the chain executor grants exactly what the adapter declares
        so a planned step can actually run instead of being denied.
        """
        adapter = self._engine.adapter_for(tool_id) if self._engine is not None else None
        descriptor = getattr(adapter, "descriptor", None) if adapter is not None else None
        requested = tuple(getattr(descriptor, "permissions", ()) or ()) if descriptor is not None else ()
        # An adapter with no declared permissions is a no-permission step.
        return requested or ("none",)

    @staticmethod
    def _step_target(step: Any, target: str, derived: dict[str, list[str]]) -> str:
        explicit = step.inputs.get("target") if step.inputs else None
        if isinstance(explicit, str) and explicit:
            return explicit
        # A dependent step consumes the first discovered host/URL from its
        # predecessors when no explicit target was provided.
        for targets in derived.values():
            if targets:
                return targets[0]
        return target

    def _select_fallback(self, step: Any, current_tool: str) -> str:
        """Return a capability-equivalent fallback with a registered adapter."""
        if self._tip is None:
            return ""
        for recommendation in self._tip.recommend(step.capability):
            if recommendation.tool_id == current_tool:
                continue
            if (
                recommendation.kind.value in ("fallback", "alternative", "replacement")
                and self._engine.adapter_for(recommendation.tool_id) is not None
            ):
                return recommendation.tool_id
        return ""

    # -- observation projection ----------------------------------------------

    def _extract_observations(self, step: Any, context: Any, result: Any) -> list[CanonicalObservation]:
        output = getattr(result, "output", None)
        if output is None:
            return []
        timestamp = utcnow_iso()
        kind = _CAPABILITY_KIND.get(step.capability, "other")
        records = _payload_records(output.json)
        observations: list[CanonicalObservation] = []
        seen: set[str] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            value = _record_value(record)
            if not value:
                continue
            normalized = _normalize_value(value)
            correlation_key = f"{kind}:{context.target}:{normalized}"
            if correlation_key in seen:
                continue
            seen.add(correlation_key)
            observations.append(
                CanonicalObservation(
                    observation_id=generate_id(),
                    target_id=context.target,
                    tool_id=context.tool_id,
                    tool_version=context.tool_version,
                    observation_kind=kind,
                    value=str(value),
                    normalized_value=normalized,
                    confidence=_record_confidence(record),
                    timestamp=timestamp,
                    source=context.tool_id,
                    raw_artifact_reference=f"exec://{context.execution_id}/stdout",
                    correlation_key=correlation_key,
                    provenance={
                        "source": context.tool_id,
                        "execution_id": context.execution_id,
                        "mission_id": context.mission_id or "",
                        "target_id": context.target,
                        "timestamp": timestamp,
                        "raw_artifact_reference": f"exec://{context.execution_id}/stdout",
                    },
                )
            )
        return observations


def _payload_records(payload: Any) -> list[Any]:
    """Flatten parsed records from a tool JSON payload."""
    if not isinstance(payload, dict):
        return []
    records: list[Any] = []
    for key in _RECORD_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
        elif key == "content" and isinstance(value, dict):
            inner = value.get("requests")
            if isinstance(inner, list):
                records.extend(item for item in inner if isinstance(item, dict))
        elif key == "secrets" and isinstance(value, dict):
            inner = value.get("findings")
            if isinstance(inner, list):
                records.extend(item for item in inner if isinstance(item, dict))
    return records


def _record_value(record: dict[str, Any]) -> str:
    for field in _VALUE_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value:
            return value
    nested = record.get("value")
    if isinstance(nested, dict):
        return _record_value(nested)
    return ""


def _normalize_value(value: str) -> str:
    return value.strip().rstrip("/")


def _record_confidence(record: dict[str, Any]) -> float:
    try:
        confidence = float(record.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    if record.get("requires_validation") is True:
        return min(confidence, 0.5)
    return confidence if 0.0 < confidence <= 1.0 else 1.0


def _derived_targets(observations: list[CanonicalObservation]) -> list[str]:
    """Return host/URL observations that can feed dependent steps."""
    targets: list[str] = []
    for observation in observations:
        if observation.observation_kind in ("domain", "ip", "url"):
            targets.append(observation.normalized_value)
    return targets


def _execution_record(context: Any, result: Any) -> Any:
    """Build a :class:`ToolExecutionResult` for a completed step."""
    from hunterx.domain.tool_intelligence import ToolExecutionResult

    return ToolExecutionResult(
        execution_id=context.execution_id,
        tool_id=context.tool_id,
        tool_version=context.tool_version,
        mission_id=context.mission_id,
        target_id=context.target,
        started_at=result.started_at,
        completed_at=result.completed_at,
        exit_status=result.status.value,
        raw_output_reference=f"exec://{context.execution_id}/stdout",
        stdout_reference=f"exec://{context.execution_id}/stdout",
        stderr_reference=f"exec://{context.execution_id}/stderr",
        structured_output=getattr(result.output, "json", None) or {},
        errors=(result.error,) if result.error else (),
        resource_usage={"duration_ms": float(result.duration_ms), "retry_count": float(result.retry_count)},
        provenance={
            "source": context.tool_id,
            "execution_id": context.execution_id,
            "mission_id": context.mission_id or "",
            "target_id": context.target,
        },
    )


def _chain_status(chain: ToolChain, completed: list[str], failed: list[str]) -> ChainStatus:
    total = len(chain.steps)
    if len(completed) == total:
        return ChainStatus.COMPLETED
    if not failed:
        return ChainStatus.PARTIAL
    if not completed:
        return ChainStatus.FAILED
    return ChainStatus.PARTIAL


__all__ = ["ChainExecutor"]
