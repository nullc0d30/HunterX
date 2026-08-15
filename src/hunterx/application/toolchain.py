# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Full toolchain application service.

The single use-case facade the CLI and API call to interact with the complete
authorized offensive-security toolchain. Every capability is a pure read or a
guarded execution:

- catalog: ``list_tools``, ``show_tool``, ``tool_capabilities``,
  ``capabilities``, ``health``, ``versions``, ``requirements``, ``provenance``.
- decision: ``recommend``, ``strategies``, ``chain``.
- execution: ``execute``, ``execution_status``, ``execution_output``,
  ``inspect_result``.
- offline replay: ``parse``, ``normalize``.

Executions are structured and scoped: targets are passed as typed arguments
and results are stored with canonical output semantics. Tool failure is never
reported as "target is safe".
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any

from hunterx.domain.events.types import (
    ToolExecutionCompletedEvent,
    ToolExecutionFailedEvent,
    ToolExecutionStartedEvent,
    ToolOutputNormalizedEvent,
    ToolOutputParsedEvent,
    ToolOutputReceivedEvent,
    ToolRecommendationCreatedEvent,
)
from hunterx.domain.exceptions import ToolExecutionError, ToolNotFoundError
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.tool_intelligence import (
    ToolExecutionResult,
    ToolOutputSemantics,
    ToolStrategy,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

__all__ = ["ToolchainService"]


class ToolchainService:
    """Framework-agnostic facade over the toolchain.

    Composes the Tool Intelligence Platform (TIP) and the Tool Integration SDK
    execution engine behind JSON-safe use cases. Returns plain dictionaries so
    the CLI renderer and API serializers consume identical payloads.
    """

    def __init__(
        self,
        tip: ToolIntelligenceAPI,
        engine: ExecutionEngine | None = None,
        event_bus: EventBusPort | None = None,
        *,
        max_stored_executions: int = 500,
        mastery: Any = None,
    ) -> None:
        self._tip = tip
        self._engine = engine
        self._event_bus = event_bus
        self._mastery = mastery
        self._executions: dict[str, dict[str, Any]] = {}
        self._max_stored = max(1, max_stored_executions)

    # -- consolidated contracts (Sprint 034.5) ------------------------------

    def contract(self, tool_id: str) -> dict[str, Any]:
        """Return the consolidated machine-readable contract for ``tool_id``.

        Raises :class:`ToolNotFoundError` when the tool is unknown. The
        contract aggregates the master profile, knowledge, argument builder,
        scope/execution/resource models, exit-code mapping, parser/normalizer,
        error/retry/artifact handling, evidence mapping and downstream chaining
        into one envelope.
        """
        self._require_tool(tool_id)
        if self._mastery is not None and callable(getattr(self._mastery, "contract", None)):
            contract = self._mastery.contract(tool_id)
            if contract is not None:
                return dict(contract)
        return self._contract_from_tip(tool_id)

    def contracts(self) -> list[dict[str, Any]]:
        """Return the consolidated contract for every registered tool.

        Mastery-backed tools return the full consolidated contract; tools that
        exist only in the TIP (in-process capability services) fall back to the
        TIP-derived contract so every registered tool has one.
        """
        contracts: dict[str, dict[str, Any]] = {}
        if self._mastery is not None and callable(getattr(self._mastery, "contracts", None)):
            for contract in self._mastery.contracts():
                contracts[str(contract.get("tool_id", ""))] = contract
        for tool_id in self._tool_ids():
            if tool_id in contracts:
                continue
            contracts[tool_id] = self._contract_from_tip(tool_id)
        return list(contracts.values())

    def contract_gaps(self) -> dict[str, list[str]]:
        """Return per-tool missing minimum contract dimensions.

        Uses the same minimum-dimension gate as the certification suite: a
        dimension is a gap only when the consolidated contract leaves it
        empty. Informational fields (false-positive notes) are not gated.
        """
        gaps: dict[str, list[str]] = {}
        for contract in self.contracts():
            tool_id = str(contract.get("tool_id", ""))
            missing = _missing_contract_dimensions(contract)
            if missing:
                gaps[tool_id] = missing
        return gaps

    # -- catalog ------------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        """Return a compact catalog entry for every registered tool."""
        return [
            {
                "tool_id": metadata.tool_id,
                "display_name": metadata.display_name,
                "category": metadata.category,
                "subcategory": metadata.subcategory,
                "version": metadata.version,
                "vendor": metadata.vendor,
                "description": metadata.description,
                "state": self._state_name(metadata.tool_id),
                "capabilities": self._tip.registry.capabilities_for(metadata.tool_id),
                "installed": self._engine is not None
                and self._engine.adapter_for(metadata.tool_id) is not None,
            }
            for metadata in self._tip.list_tools()
        ]

    def show_tool(self, tool_id: str) -> dict[str, Any]:
        """Return the full knowledge contract for ``tool_id``."""
        self._require_tool(tool_id)
        metadata = self._tip.get_tool(tool_id)
        knowledge = self._tip.get_knowledge(tool_id)
        state = self._tip.get_state(tool_id)
        compatibility = self._tip.registry.get_compatibility(tool_id)
        health = self._tip.health(tool_id)
        reliability = self._tip.reliability(tool_id)
        availability = self._tip.registry.get_availability_report(tool_id)
        return {
            "tool_id": tool_id,
            "identity": asdict(metadata) if metadata is not None else {},
            "knowledge": _knowledge_dict(knowledge) if knowledge is not None else {},
            "compatibility": asdict(compatibility) if compatibility is not None else {},
            "state": asdict(state) if state is not None else {},
            "health": asdict(health) if health is not None else {},
            "reliability": asdict(reliability) if reliability is not None else {},
            "availability": asdict(availability) if availability is not None else {},
            "requirements": self.requirements(tool_id),
            "provenance": self.provenance(tool_id),
        }

    def tool_capabilities(self, tool_id: str) -> list[str]:
        """Return the capability ids provided by ``tool_id``."""
        self._require_tool(tool_id)
        return self._tip.registry.capabilities_for(tool_id)

    def capabilities(self, *, term: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Return the capability catalog, optionally filtered by ``term``."""
        matches = self._tip.search_capabilities(term) if term else self._tip.capabilities_engine.search("", limit=limit)
        if not term:
            matches = matches[:limit]
        return [
            {
                "capability_id": cap.capability_id,
                "name": cap.name,
                "category": cap.category,
                "subcategory": cap.subcategory,
                "description": cap.description,
                "risk_level": cap.risk_level,
                "providers": self._tip.tools_by_capability(cap.capability_id),
                "aliases": list(self._tip.vocabulary.variants(cap.capability_id)),
            }
            for cap in matches
        ]

    def canonical_capability(self, capability_id: str) -> str:
        """Return the canonical form of a capability id across the toolchain."""
        return self._tip.vocabulary.canonical(capability_id)

    def health(self, tool_id: str = "") -> dict[str, Any]:
        """Return health statistics for one tool or every registered tool."""
        if tool_id:
            self._require_tool(tool_id)
            stats = self._tip.health(tool_id)
            availability = self._tip.registry.get_availability_report(tool_id)
            sdk = self._engine_health(tool_id)
            return {
                "tool_id": tool_id,
                "stats": asdict(stats) if stats is not None else {},
                "availability": asdict(availability) if availability is not None else {},
                "sdk": sdk,
            }
        tools = []
        for metadata in self._tip.list_tools():
            tools.append(self.health(metadata.tool_id))
        return {"tools": tools, "count": len(tools)}

    def versions(self, tool_id: str = "") -> dict[str, Any]:
        """Return known, installed and constraint version facts."""
        if tool_id:
            self._require_tool(tool_id)
            metadata = self._tip.get_tool(tool_id)
            knowledge = self._tip.get_knowledge(tool_id)
            constraints = tuple(knowledge.version_constraints) if knowledge is not None else ()
            installed = self._engine.versions.installed(tool_id) if self._engine is not None else None
            state = self._tip.get_state(tool_id)
            compatible = all(
                (self._engine is None or self._engine.versions.satisfies(tool_id, constraint))
                for constraint in constraints
            )
            return {
                "tool_id": tool_id,
                "known_version": metadata.version if metadata is not None else "",
                "installed_version": installed or (state.installed_version if state is not None else "") or "",
                "constraints": list(constraints),
                "compatible": bool(compatible),
            }
        return {
            "tools": [self.versions(metadata.tool_id) for metadata in self._tip.list_tools()],
            "count": len(self._tip.list_tools()),
        }

    def requirements(self, tool_id: str) -> dict[str, Any]:
        """Return the execution requirements of ``tool_id``."""
        self._require_tool(tool_id)
        knowledge = self._tip.get_knowledge(tool_id)
        if knowledge is None:
            return {"tool_id": tool_id}
        resources = knowledge.resource_requirements
        safety = knowledge.safety_profile
        scope = knowledge.scope_profile
        invocation = knowledge.invocation_contract
        return {
            "tool_id": tool_id,
            "inputs": {
                "accepts": list(knowledge.inputs.accepts),
                "required": list(knowledge.inputs.required),
                "optional": list(knowledge.inputs.optional),
            },
            "outputs": {
                "formats": list(knowledge.outputs.formats),
                "parser": knowledge.outputs.parser,
                "normalizer": knowledge.outputs.normalizer,
            },
            "authentication": knowledge.authentication_requirements,
            "privileges": knowledge.privileges_required,
            "dependencies": [asdict(dep) for dep in knowledge.dependencies],
            "installation": list(knowledge.installation_requirements),
            "resource_requirements": asdict(resources) if resources is not None else {},
            "safety_profile": asdict(safety) if safety is not None else {},
            "scope_profile": asdict(scope) if scope is not None else {},
            "invocation_contract": asdict(invocation) if invocation is not None else {},
            "rate_limit": _rate_limit_dict(resources),
        }

    def provenance(self, tool_id: str) -> dict[str, Any]:
        """Return the provenance (parser/normalizer/adapter/version) of ``tool_id``."""
        self._require_tool(tool_id)
        knowledge = self._tip.get_knowledge(tool_id)
        metadata = self._tip.get_tool(tool_id)
        return {
            "tool_id": tool_id,
            "adapter_id": knowledge.adapter_id if knowledge is not None else "",
            "parser_id": knowledge.parser_id if knowledge is not None else "",
            "normalizer_id": knowledge.normalizer_id if knowledge is not None else "",
            "knowledge_version": knowledge.knowledge_version if knowledge is not None else "",
            "version_constraints": list(knowledge.version_constraints) if knowledge is not None else [],
            "known_version": metadata.version if metadata is not None else "",
            "alternatives": list(knowledge.alternative_tools) if knowledge is not None else [],
            "provenance": dict(knowledge.provenance) if knowledge is not None else {},
        }

    # -- decision support ---------------------------------------------------

    def recommend(self, capability_id: str) -> list[dict[str, Any]]:
        """Return best/alternative/fallback recommendations for ``capability_id``."""
        recommendations = self._tip.recommend(capability_id)
        payload = [
            {
                "tool_id": rec.tool_id,
                "kind": rec.kind.value,
                "score": rec.score,
                "reason": rec.reason,
            }
            for rec in recommendations
        ]
        if payload:
            first = payload[0]
            self._publish(
                ToolRecommendationCreatedEvent(
                    capability_id,
                    str(first["tool_id"]),
                    kind=str(first["kind"]),
                    score=float(first["score"]),
                    reason=str(first["reason"]),
                )
            )
        return payload

    def strategies(self, capability_id: str) -> dict[str, Any]:
        """Return the canonical selection strategy for ``capability_id``.

        The strategy declares the primary tool, ordered fallbacks,
        complementary tools and the merge policy for correlated outputs.
        """
        recommendations = self._tip.recommend(capability_id)
        primary = ""
        fallbacks: list[str] = []
        complementary: list[str] = []
        for rec in recommendations:
            if rec.kind.value == "best":
                primary = rec.tool_id
            elif rec.kind.value == "fallback" or rec.kind.value == "alternative":
                fallbacks.append(rec.tool_id)
            elif rec.kind.value == "complementary":
                complementary.append(rec.tool_id)
        strategy = ToolStrategy(
            capability=capability_id,
            primary=primary,
            fallbacks=tuple(dict.fromkeys(fallbacks)),
            complementary=tuple(dict.fromkeys(complementary)),
            merge_policy="deduplicate",
            rationale="primary tool first; fallbacks on failure; complementary outputs correlated, never merged blindly",
        )
        return asdict(strategy)

    def chain(self, objective: str, capabilities: list[str], *, mission_id: str = "", scope: str = "") -> dict[str, Any]:
        """Plan a dependency-aware tool chain for ``objective``."""
        chain = self._tip.plan_chain(
            objective,
            capabilities=tuple(capabilities),
            mission_id=mission_id,
            scope=scope,
        )
        return {
            "chain_id": chain.chain_id,
            "objective": chain.objective,
            "mission_id": chain.mission_id,
            "steps": [
                {
                    "step_id": step.step_id,
                    "tool_id": step.tool_id,
                    "capability": step.capability,
                    "outputs": list(step.outputs),
                    "on_success": step.on_success.value,
                    "on_failure": step.on_failure.value,
                    "safety_class": step.safety_class.value,
                }
                for step in chain.steps
            ],
            "dependencies": {key: list(values) for key, values in chain.dependencies.items()},
            "scope": chain.scope,
        }

    # -- chained execution (Sprint 034.5) -----------------------------------

    def execute_chain(
        self,
        objective: str,
        capabilities: list[str],
        target: str,
        *,
        mission_id: str = "",
        scope: str = "",
        target_type: str = "",
        parameters: dict[str, Any] | None = None,
        timeout: float = 0.0,
        allow_fallback: bool = True,
        chain_id: str = "",
    ) -> dict[str, Any]:
        """Plan and execute an end-to-end tool chain against ``target``.

        Every step's raw output and canonical observations (with provenance)
        are preserved. Failures are classified and a capability-equivalent
        fallback is attempted once when ``allow_fallback``. Returns a
        JSON-safe chain report.
        """
        if self._engine is None:
            raise ToolExecutionError("no execution engine wired for chain execution")
        chain = self._tip.plan_chain(
            objective,
            capabilities=tuple(capabilities),
            mission_id=mission_id,
            scope=scope,
            chain_id=chain_id,
        )
        executor = self._chain_executor()
        result = executor.execute(
            chain,
            target=target,
            target_type=target_type,
            mission_id=mission_id,
            scope=scope,
            parameters=parameters,
            timeout=timeout,
            allow_fallback=allow_fallback,
        )
        return _chain_result_dict(chain, result)

    # -- execution ----------------------------------------------------------

    def execute(
        self,
        tool_id: str,
        target: str,
        *,
        parameters: dict[str, Any] | None = None,
        mission_id: str = "",
        scope: str = "",
        target_type: str = "",
        profile: str = "",
        timeout: float = 0.0,
        tool_version: str = "",
    ) -> dict[str, Any]:
        """Execute ``tool_id`` against ``target`` and store the outcome.

        The execution is structured: ``target`` and ``parameters`` are typed
        arguments, never shell fragments. Returns an ``execution_id`` for
        later :meth:`execution_status` / :meth:`inspect_result` queries.
        """
        self._require_tool(tool_id)
        if self._engine is None or self._engine.adapter_for(tool_id) is None:
            raise ToolExecutionError(f"no execution adapter registered for tool '{tool_id}'")

        builder = (
            ExecutionContextBuilder(tool_id=tool_id, target=target)
            .with_mission(mission_id)
            .with_profile(profile)
            .with_parameters(dict(parameters or {}))
            .with_permissions(_adapter_permissions(self._engine, tool_id))
        )
        if target_type:
            builder = builder.with_target_type(target_type)
        if timeout > 0:
            builder = builder.with_timeout(timeout)
        if tool_version:
            builder = builder.with_tool_version(tool_version)
        context = builder.build()

        self._publish(
            ToolExecutionStartedEvent(
                context.execution_id,
                tool_id,
                mission_id=mission_id,
                scope_id=scope,
            )
        )
        outcome = self._engine.execute(context)
        return self._record(context, outcome.result, scope)

    def execution_status(self, execution_id: str) -> dict[str, Any]:
        """Return the current status of a stored execution."""
        record = self._executions.get(execution_id)
        if record is None:
            raise ToolExecutionError(f"unknown execution '{execution_id}'")
        return {
            "execution_id": execution_id,
            "tool_id": record.get("tool_id", ""),
            "status": record.get("status", "unknown"),
            "semantics": record.get("semantics", "unknown"),
            "exit_code": record.get("exit_code"),
            "started_at": record.get("started_at", ""),
            "completed_at": record.get("completed_at", ""),
            "duration_ms": record.get("duration_ms", 0),
            "error": record.get("error", ""),
        }

    def execution_output(self, execution_id: str) -> dict[str, Any]:
        """Return the captured output summary of a stored execution."""
        record = self._executions.get(execution_id)
        if record is None:
            raise ToolExecutionError(f"unknown execution '{execution_id}'")
        return {
            "execution_id": execution_id,
            "tool_id": record.get("tool_id", ""),
            "formats": record.get("formats", []),
            "size_bytes": record.get("size_bytes", 0),
            "stdout_preview": record.get("stdout_preview", ""),
            "stderr_preview": record.get("stderr_preview", ""),
            "artifact_count": record.get("artifact_count", 0),
        }

    def inspect_result(self, execution_id: str) -> dict[str, Any]:
        """Return the full stored execution profile and result."""
        record = self._executions.get(execution_id)
        if record is None:
            raise ToolExecutionError(f"unknown execution '{execution_id}'")
        return dict(record)

    # -- offline replay -----------------------------------------------------

    def parse(self, tool_id: str, raw: str, *, target: str = "") -> dict[str, Any]:
        """Parse saved raw output into structured records without executing.

        Dispatches to the tool's registered parser when an adapter is known;
        otherwise falls back to generic JSON/JSONL parsing.
        """
        adapter = self._parser_adapter(tool_id)
        parsed: list[Any] = []
        if adapter is not None and callable(getattr(adapter, "parse_output", None)):
            context = ExecutionContext(tool_id=tool_id, target=target)
            result = CommandResult(returncode=0, stdout=raw or "")
            parsed = [_serialize(record) for record in adapter.parse_output(context, result)]
        else:
            from hunterx.tools.parser import ParserEngine

            parsed = ParserEngine().parse(tool_id, raw)
        self._publish(ToolOutputParsedEvent("offline", tool_id, parser_id=tool_id, records=len(parsed)))
        return {"tool_id": tool_id, "records": parsed, "count": len(parsed)}

    def normalize(self, tool_id: str, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Normalize parsed records into canonical observations."""
        from hunterx.tools.normalizer import NormalizerEngine

        output = NormalizerEngine(default_tool=tool_id).normalize(records, tool=tool_id)
        self._publish(ToolOutputNormalizedEvent("offline", tool_id, normalizer_id=tool_id, observations=len(output.assets)))
        return {
            "tool_id": tool_id,
            "findings": [_serialize(finding) for finding in output.findings],
            "evidence": [_serialize(item) for item in output.evidence],
            "assets": output.assets,
            "counts": {
                "findings": len(output.findings),
                "evidence": len(output.evidence),
                "assets": len(output.assets),
            },
        }

    # -- internals ----------------------------------------------------------

    def _chain_executor(self) -> Any:
        from hunterx.tools.intelligence.chaining import ChainExecutor

        if self._engine is None:
            raise ToolExecutionError("no execution engine wired for chain execution")
        return ChainExecutor(self._engine, tip=self._tip, event_bus=self._event_bus)

    def _tool_ids(self) -> list[str]:
        return [metadata.tool_id for metadata in self._tip.list_tools()]

    def _contract_from_tip(self, tool_id: str) -> dict[str, Any]:
        """Build a complete best-effort contract directly from TIP knowledge.

        Used only when no mastery facade is wired, or for tools that exist
        only in the TIP (in-process capability services). Covers every minimum
        dimension: scope model, error mapping, retry policy, evidence mapping
        and downstream chaining are derived from the TIP knowledge and
        registry when present, with explicit defaults otherwise.
        """
        metadata = self._tip.get_tool(tool_id)
        knowledge = self._tip.get_knowledge(tool_id)
        evidence = self._tip.registry.evidence_mappings_for(tool_id)
        state = self._tip.get_state(tool_id)
        scope = knowledge.scope_profile if knowledge is not None else None
        safety = knowledge.safety_profile if knowledge is not None else None
        resources = knowledge.resource_requirements if knowledge is not None else None
        timeout = 0.0
        for candidate in (resources,):
            value = getattr(candidate, "timeout", 0.0) or 0.0
            timeout = max(timeout, value)
        if timeout == 0.0 and state is not None and state.state.value in {
            "available", "verified", "installed",
        }:
            timeout = 300.0
        executable = self._engine is not None and self._engine.adapter_for(tool_id) is not None
        evidence_mapping = [asdict(mapping) for mapping in evidence]
        if not evidence_mapping and knowledge is not None:
            evidence_mapping = _default_evidence_mappings(tool_id, list(knowledge.capabilities))
        return {
            "tool_id": tool_id,
            "identity": asdict(metadata) if metadata is not None else {},
            "version": metadata.version if metadata is not None else "",
            "category": metadata.category if metadata is not None else "",
            "subcategory": metadata.subcategory if metadata is not None else "",
            "capabilities": list(knowledge.capabilities) if knowledge is not None else [],
            "support_level": state.state.value if state is not None else "knowledge-only",
            "requirements": self.requirements(tool_id),
            "input_schema": {
                "accepts": list(knowledge.inputs.accepts) if knowledge is not None else [],
                "required": list(knowledge.inputs.required) if knowledge is not None else [],
                "optional": list(knowledge.inputs.optional) if knowledge is not None else [],
            },
            "argument_builder": {
                "cli_binary": knowledge.cli_binary if knowledge is not None else "",
                "arguments": [asdict(argument) for argument in knowledge.arguments] if knowledge is not None else [],
            },
            "scope_model": {
                "scope_requirements": "",
                "follows_redirects": scope.follows_redirects if scope is not None else False,
                "redirect_scope": scope.redirect_scope if scope is not None else "inherit",
                "expands_scope": scope.expands_scope if scope is not None else False,
                "network_boundary": scope.network_boundary if scope is not None else "inherit",
                "safety_class": safety.safety_class.value if safety is not None else "passive",
                "destructive": safety.destructive if safety is not None else False,
                "requires_authorization": safety.requires_authorization if safety is not None else False,
            },
            "execution_profile": {
                "execution_type": metadata.execution_type.value if metadata is not None else "unknown",
                "adapter_id": knowledge.adapter_id if knowledge is not None else "",
                "executable": executable,
            },
            "timeout": timeout,
            "resource_limits": self.requirements(tool_id).get("resource_requirements", {}),
            "output_formats": list(knowledge.outputs.formats) if knowledge is not None else [],
            "exit_code_mapping": ["0: completed", "1: completed with warnings or no findings", "2: error"],
            "parser": {"parser_id": knowledge.parser_id if knowledge is not None else ""},
            "normalizer": {"normalizer_id": knowledge.normalizer_id if knowledge is not None else ""},
            "artifact_handling": {
                "evidence_capture": list(knowledge.outputs.evidence_capture) if knowledge is not None else []
            },
            "error_mapping": {
                "error_indicators": [],
                "warning_indicators": [],
                "partial_result_indicators": [],
                "classification": {"errors": "failure", "warnings": "degraded", "partial": "partial-result"},
            },
            "retry_policy": {
                "max_attempts": 2 if executable else 1,
                "retryable_kinds": ["retryable", "timeout", "resource-exhausted"],
                "strategy": "exponential-backoff",
                "base_delay_s": 1.0,
                "max_delay_s": 60.0,
                "fallback": list(knowledge.alternative_tools) if knowledge is not None else [],
            },
            "evidence_mapping": evidence_mapping,
            "downstream_capabilities": {
                "alternatives": list(knowledge.alternative_tools) if knowledge is not None else []
            },
            "false_positive_risks": [],
            "false_negative_risks": [],
            "provenance": {},
        }

    def _record(self, context: ExecutionContext, result: Any, scope: str) -> dict[str, Any]:
        """Persist an execution outcome in the in-memory store."""
        output = result.output
        formats = sorted(fmt.value for fmt in output.formats)
        size_bytes = _output_size(output)
        semantics = _semantics_for(result).value
        self._publish(
            ToolOutputReceivedEvent(
                context.execution_id,
                context.tool_id,
                formats=formats,
                size_bytes=size_bytes,
            )
        )
        profile = ToolExecutionResult(
            execution_id=context.execution_id,
            tool_id=context.tool_id,
            tool_version=context.tool_version,
            mission_id=context.mission_id,
            target_id=context.target,
            scope_id=scope,
            started_at=result.started_at,
            completed_at=result.completed_at,
            exit_status=str(result.status.value),
            stdout_reference=f"exec://{context.execution_id}/stdout",
            stderr_reference=f"exec://{context.execution_id}/stderr",
            errors=(str(result.error),) if result.error else (),
            resource_usage=_resource_usage(result),
        )
        record = {
            "execution_id": context.execution_id,
            "tool_id": context.tool_id,
            "tool_version": context.tool_version,
            "mission_id": context.mission_id,
            "scope": scope,
            "target": context.target,
            "status": result.status.value,
            "semantics": semantics,
            "exit_code": output.exit_code,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "duration_ms": result.duration_ms,
            "error": result.error,
            "failure_kind": result.failure_kind.value if result.failure_kind is not None else "",
            "formats": formats,
            "size_bytes": size_bytes,
            "stdout_preview": (output.stdout or "")[:2000],
            "stderr_preview": (output.stderr or "")[:2000],
            "artifact_count": len(getattr(result, "artifacts", ())),
            "profile": _dataclass_to_dict(profile),
            "retry_count": result.retry_count,
            "trace": list(getattr(result, "trace", [])),
        }
        self._evict_oldest()
        self._executions[context.execution_id] = record
        if result.ok:
            self._publish(
                ToolExecutionCompletedEvent(
                    context.execution_id,
                    context.tool_id,
                    exit_code=output.exit_code,
                    semantics=semantics,
                    duration_ms=result.duration_ms,
                )
            )
        else:
            self._publish(
                ToolExecutionFailedEvent(
                    context.execution_id,
                    context.tool_id,
                    failure_kind=result.failure_kind.value if result.failure_kind is not None else "error",
                    message=result.error,
                )
            )
        return self.execution_status(context.execution_id)

    def _evict_oldest(self) -> None:
        if len(self._executions) <= self._max_stored:
            return
        for key in list(self._executions)[: len(self._executions) - self._max_stored]:
            self._executions.pop(key, None)

    def _parser_adapter(self, tool_id: str) -> Any:
        if self._engine is None:
            return None
        adapter = self._engine.adapter_for(tool_id)
        if adapter is None:
            return None
        return getattr(adapter, "tool", adapter)

    def _engine_health(self, tool_id: str) -> dict[str, Any]:
        if self._engine is None:
            return {"tool_id": tool_id, "healthy": False, "reason": "no execution engine", "version": None}
        adapter = self._engine.adapter_for(tool_id)
        installed = self._engine.versions.installed(tool_id)
        return {
            "tool_id": tool_id,
            "adapter_registered": adapter is not None,
            "installed_version": installed or "",
            "healthy": self._engine.health_check(tool_id) if installed else False,
        }

    def _state_name(self, tool_id: str) -> str:
        state = self._tip.get_state(tool_id)
        return state.state.value if state is not None else "unknown"

    def _require_tool(self, tool_id: str) -> None:
        if self._tip.get_tool(tool_id) is None:
            raise ToolNotFoundError(tool_id)

    def _publish(self, event: Any) -> None:
        if self._event_bus is not None:
            self._event_bus.publish(event)


def _default_evidence_mappings(tool_id: str, capabilities: list[str]) -> list[dict[str, Any]]:
    """Derive canonical evidence mappings from capability ids.

    Used for tools whose TIP record carries no explicit evidence mapping so
    the consolidated contract always exposes the evidence/intelligence
    dimension.
    """
    from hunterx.tools.mastery.knowledge_fixtures import (
        _CAPABILITY_EVIDENCE_TYPE,
        _CAPABILITY_OBSERVATION_KIND,
        _VALIDATION_REQUIRED,
    )

    mappings: list[dict[str, Any]] = []
    for capability in capabilities:
        if capability not in _CAPABILITY_EVIDENCE_TYPE:
            continue
        mappings.append(
            {
                "capability": capability,
                "observation_kind": _CAPABILITY_OBSERVATION_KIND.get(capability, "other"),
                "evidence_type": _CAPABILITY_EVIDENCE_TYPE.get(capability, "observation"),
                "requires_validation": capability in _VALIDATION_REQUIRED,
                "strength": "detection",
                "ceiling": 0.5,
            }
        )
    if not mappings:
        # Generic catch-all so the evidence dimension is never empty.
        mappings.append(
            {
                "capability": capabilities[0] if capabilities else "observation",
                "observation_kind": "other",
                "evidence_type": "observation",
                "requires_validation": any(
                    capability in _VALIDATION_REQUIRED for capability in capabilities
                ),
                "strength": "detection",
                "ceiling": 0.5,
            }
        )
    return mappings


def _missing_contract_dimensions(contract: dict[str, Any]) -> list[str]:
    """Return the minimum contract dimensions missing from a contract dict."""
    minimum = (
        "identity", "version", "category", "capabilities", "input_schema",
        "argument_builder", "scope_model", "output_formats", "parser",
        "normalizer", "error_mapping", "retry_policy", "evidence_mapping",
        "downstream_capabilities",
    )
    missing: list[str] = []
    for key in minimum:
        value = contract.get(key)
        if value in (None, "", [], {}):
            missing.append(key)
    if contract.get("support_level") in {
        "fully-supported", "execution-only", "partial-support",
    } and not contract.get("timeout"):
        missing.append("timeout")
    return missing


def _adapter_permissions(engine: Any, tool_id: str) -> tuple[str, ...]:
    """Return the permission flags a tool's adapter requires.

    The sandbox denies any execution whose context does not explicitly grant
    the adapter-declared permission (network/filesystem/...). Direct tool
    execution through ``hunterx tools execute`` must grant exactly what the
    adapter declares so the tool can actually run.
    """
    if engine is None:
        return ("none",)
    adapter = engine.adapter_for(tool_id)
    if adapter is None:
        return ("none",)
    requested = tuple(getattr(getattr(adapter, "descriptor", None), "permissions", ()) or ())
    return requested or ("none",)


def _chain_result_dict(chain: Any, result: Any) -> dict[str, Any]:
    """Serialize a :class:`ToolChainResult` into a JSON-safe report."""
    return {
        "chain_id": chain.chain_id,
        "objective": chain.objective,
        "mission_id": chain.mission_id,
        "status": result.status.value,
        "completed_steps": list(result.completed_steps),
        "failed_steps": list(result.failed_steps),
        "skipped_steps": list(result.skipped_steps),
        "steps": [
            {
                "step_id": step.step_id,
                "tool_id": step.tool_id,
                "status": step.status.value,
                "error": step.error,
                "observations": [
                    {
                        "observation_id": observation.observation_id,
                        "target_id": observation.target_id,
                        "tool_id": observation.tool_id,
                        "observation_kind": observation.observation_kind,
                        "value": observation.value,
                        "normalized_value": observation.normalized_value,
                        "confidence": observation.confidence,
                        "timestamp": observation.timestamp,
                        "raw_artifact_reference": observation.raw_artifact_reference,
                        "correlation_key": observation.correlation_key,
                        "provenance": dict(observation.provenance),
                    }
                    for observation in step.observations
                ],
                "execution": _execution_dict(step.execution),
            }
            for step in result.step_results
        ],
        "observation_count": sum(len(step.observations) for step in result.step_results),
    }


def _execution_dict(execution: Any) -> dict[str, Any]:
    if execution is None:
        return {}
    return {
        "execution_id": execution.execution_id,
        "tool_id": execution.tool_id,
        "tool_version": execution.tool_version,
        "mission_id": execution.mission_id,
        "target_id": execution.target_id,
        "exit_status": execution.exit_status,
        "raw_output_reference": execution.raw_output_reference,
        "errors": list(execution.errors),
        "resource_usage": dict(execution.resource_usage),
    }


def _knowledge_dict(knowledge: Any) -> dict[str, Any]:
    """Serialize a :class:`ToolKnowledge` profile into a JSON-safe mapping."""
    return {
        "tool_id": knowledge.tool_id,
        "purpose": knowledge.purpose,
        "capabilities": list(knowledge.capabilities),
        "supported_assessments": list(knowledge.supported_assessments),
        "supported_mission_profiles": list(knowledge.supported_mission_profiles),
        "inputs": {
            "accepts": list(knowledge.inputs.accepts),
            "required": list(knowledge.inputs.required),
            "optional": list(knowledge.inputs.optional),
            "max_targets_per_invocation": knowledge.inputs.max_targets_per_invocation,
        },
        "outputs": {
            "formats": list(knowledge.outputs.formats),
            "parser": knowledge.outputs.parser,
            "normalizer": knowledge.outputs.normalizer,
            "evidence_capture": list(knowledge.outputs.evidence_capture),
        },
        "cli_binary": knowledge.cli_binary,
        "arguments": [asdict(argument) for argument in knowledge.arguments],
        "modes": [asdict(mode) for mode in knowledge.modes],
        "safe_mode": knowledge.safe_mode,
        "aggressive_mode": knowledge.aggressive_mode,
        "authentication_requirements": knowledge.authentication_requirements,
        "privileges_required": knowledge.privileges_required,
        "limitations": list(knowledge.limitations),
        "known_issues": list(knowledge.known_issues),
        "performance_notes": knowledge.performance_notes,
        "installation_requirements": list(knowledge.installation_requirements),
        "alternative_tools": list(knowledge.alternative_tools),
        "recommended_usage": list(knowledge.recommended_usage),
        "common_mistakes": list(knowledge.common_mistakes),
        "examples": list(knowledge.examples),
        "supported_targets": list(knowledge.supported_targets),
        "supported_protocols": list(knowledge.supported_protocols),
        "supported_vulnerabilities": list(knowledge.supported_vulnerabilities),
        "parser_id": knowledge.parser_id,
        "normalizer_id": knowledge.normalizer_id,
        "adapter_id": knowledge.adapter_id,
        "version_constraints": list(knowledge.version_constraints),
        "known_false_positives": list(knowledge.known_false_positives),
        "known_false_negatives": list(knowledge.known_false_negatives),
        "knowledge_version": knowledge.knowledge_version,
    }


def _semantics_for(result: Any) -> ToolOutputSemantics:
    """Classify an execution result into canonical output semantics."""
    if result.ok:
        return ToolOutputSemantics.FOUND if _has_content(result.output) else ToolOutputSemantics.NOT_FOUND
    if result.status.value == "timed-out":
        return ToolOutputSemantics.TIMEOUT
    if result.failure_kind is not None and result.failure_kind.value == "output-invalid":
        return ToolOutputSemantics.INVALID_INPUT
    return ToolOutputSemantics.ERROR


def _has_content(output: Any) -> bool:
    return any(
        (
            output.stdout,
            output.stderr,
            output.json is not None,
            output.xml,
            output.csv,
            output.txt,
            output.files,
        )
    )


def _output_size(output: Any) -> int:
    size = (
        len(output.stdout)
        + len(output.stderr)
        + len(output.xml)
        + len(output.txt)
        + len(output.yaml)
        + len(output.html)
    )
    size += len(output.binary)
    if output.json is not None:
        size += _serialize_len(output.json)
    return size


def _serialize_len(value: Any) -> int:
    try:
        import json

        return len(json.dumps(value, default=_serialize))
    except (TypeError, ValueError):
        return 0


def _resource_usage(result: Any) -> dict[str, float]:
    return {
        "duration_ms": float(result.duration_ms),
        "retry_count": float(result.retry_count),
    }


def _rate_limit_dict(resources: Any) -> dict[str, Any]:
    rate = getattr(resources, "rate_limit", None)
    return asdict(rate) if rate is not None else {}


def _dataclass_to_dict(value: Any) -> dict[str, Any]:
    """Serialize a dataclass instance, bypassing mypy's slots-dataclass quirk."""
    return asdict(value)


def _serialize(value: Any) -> Any:
    """Convert a domain value into a JSON-safe primitive."""
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in value]
    if isinstance(value, set):
        return [_serialize(item) for item in sorted(value, key=str)]
    if is_dataclass(value):
        return _serialize(asdict(value))  # type: ignore[arg-type]  # slots dataclass narrow
    if hasattr(value, "value"):
        return value.value
    return value
