# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission orchestration domain models.

The canonical mission object, its scope and exclusions, the policy envelopes
(safety, execution, tool, retry, rate-limit), the target set, and the execution
plan decomposition (phases → steps) with tool bindings and dependencies.

These are pure, storage-agnostic dataclasses. No I/O, no execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.orchestration.enums import (
    ExecutionPolicyLevel,
    MissionPhaseKind,
    MissionState,
    MissionType,
    TaskState,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class Authorization:
    """Proof and constraints of authorization for a mission.

    Attributes:
        reference: authorization reference (ticket, contract, program id).
        holder: the entity the authorization was granted to.
        status: ``authorized``, ``pending``, ``expired`` or ``revoked``.
        valid_until: UTC ISO-8601 expiry (empty = no expiry).
        note: human-readable authorization note.

    """

    reference: str = ""
    holder: str = ""
    status: str = "authorized"
    valid_until: str = ""
    note: str = ""

    @property
    def is_valid(self) -> bool:
        """Return ``True`` when the authorization is currently valid."""
        if self.status != "authorized":
            return False
        if self.valid_until:
            from hunterx.shared.time import utcnow_iso

            return self.valid_until >= utcnow_iso()[: len(self.valid_until)]
        return True


@dataclass(frozen=True, slots=True)
class MissionScope:
    """Authorized targets, explicit includes and exclusions.

    Attributes:
        roots: entry targets (domains, CIDRs, IPs, URLs) the mission may touch.
        includes: additional identifiers explicitly authorized.
        excludes: identifiers that are off-limits (exclusions always win).
        follow_subdomains: whether discovered subdomains are automatically in scope.
        follow_redirects: whether same-scope redirects are followed.

    """

    roots: tuple[str, ...] = ()
    includes: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    follow_subdomains: bool = True
    follow_redirects: bool = True

    def allows(self, identifier: str) -> bool:
        """Return ``True`` when ``identifier`` is authorized by this scope.

        Exclusions always win. Exact membership on the roots/includes decides;
        richer suffix/CIDR matching is performed by the scope guard.
        """
        if identifier in self.excludes:
            return False
        return identifier in self.roots or identifier in self.includes

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "roots": list(self.roots),
            "includes": list(self.includes),
            "excludes": list(self.excludes),
            "follow_subdomains": self.follow_subdomains,
            "follow_redirects": self.follow_redirects,
        }


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Retry policy for tool executions within a mission.

    Attributes:
        max_attempts: total attempts (1 = no retry).
        base_delay_s: initial backoff delay.
        max_delay_s: backoff ceiling.
        backoff_factor: multiplier between attempts.
        jitter: apply random jitter to backoff.

    """

    max_attempts: int = 3
    base_delay_s: float = 1.0
    max_delay_s: float = 60.0
    backoff_factor: float = 2.0
    jitter: bool = True

    def retries(self) -> int:
        """Return the number of retries permitted after the first attempt."""
        return max(0, self.max_attempts - 1)


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """Rate-limit configuration.

    A value of ``0`` means unlimited for the corresponding key.
    """

    global_per_second: float = 0.0
    mission_per_second: float = 0.0
    target_per_second: float = 0.0
    domain_per_second: float = 0.0
    ip_per_second: float = 0.0
    tool_per_second: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "global_per_second": self.global_per_second,
            "mission_per_second": self.mission_per_second,
            "target_per_second": self.target_per_second,
            "domain_per_second": self.domain_per_second,
            "ip_per_second": self.ip_per_second,
            "tool_per_second": self.tool_per_second,
        }


@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    """Safety envelope for a mission.

    Attributes:
        allowed_classes: allowed :class:`SafetyClass` values.
        forbidden_actions: action substrings that are never permitted.
        forbidden_parameter_markers: parameter markers that are never permitted.
        destructive_allowed: whether destructive behavior may be considered
            (still gated by :attr:`ExecutionPolicyLevel`).

    """

    allowed_classes: tuple[str, ...] = ("passive", "read_only", "benign_marker", "controlled")
    forbidden_actions: tuple[str, ...] = (
        "credential-dumping",
        "password-spraying",
        "credential-stuffing",
        "data-deletion",
        "database-modification",
        "persistence",
        "privilege-escalation",
        "lateral-movement",
        "malware-deployment",
        "denial-of-service",
        "data-exfiltration",
        "weaponized-exploit-execution",
    )
    forbidden_parameter_markers: tuple[str, ...] = (
        "--exec",
        "-e /bin/sh",
        "nc -e",
        "--privileged",
        "rm -rf",
        "rm -fr",
        "$(",
        "`",
    )
    destructive_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "allowed_classes": list(self.allowed_classes),
            "forbidden_actions": list(self.forbidden_actions),
            "forbidden_parameter_markers": list(self.forbidden_parameter_markers),
            "destructive_allowed": self.destructive_allowed,
        }


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    """Tool selection policy.

    Attributes:
        allowed_tools: explicit allow-list (empty = all tools allowed).
        excluded_tools: explicit deny-list.
        preferred_tools: tools to prefer when multiple providers match.
        fallback_enabled: allow capability-equivalent fallback tools.
        require_installed: only select tools with an installed/available state.

    """

    allowed_tools: tuple[str, ...] = ()
    excluded_tools: tuple[str, ...] = ()
    preferred_tools: tuple[str, ...] = ()
    fallback_enabled: bool = True
    require_installed: bool = True

    def permits(self, tool_id: str) -> bool:
        """Return ``True`` when ``tool_id`` is permitted by this policy."""
        if tool_id in self.excluded_tools:
            return False
        return not self.allowed_tools or tool_id in self.allowed_tools

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "allowed_tools": list(self.allowed_tools),
            "excluded_tools": list(self.excluded_tools),
            "preferred_tools": list(self.preferred_tools),
            "fallback_enabled": self.fallback_enabled,
            "require_installed": self.require_installed,
        }


@dataclass(frozen=True, slots=True)
class Policies:
    """The complete policy envelope of a mission."""

    execution_policy: ExecutionPolicyLevel = ExecutionPolicyLevel.SAFE_ACTIVE
    safety: SafetyPolicy = field(default_factory=SafetyPolicy)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    tool: ToolPolicy = field(default_factory=ToolPolicy)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "execution_policy": self.execution_policy.value,
            "safety": self.safety.to_dict(),
            "retry": {
                "max_attempts": self.retry.max_attempts,
                "base_delay_s": self.retry.base_delay_s,
                "max_delay_s": self.retry.max_delay_s,
                "backoff_factor": self.retry.backoff_factor,
                "jitter": self.retry.jitter,
            },
            "rate_limit": self.rate_limit.to_dict(),
            "tool": self.tool.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class TargetSet:
    """The canonical target set of a mission.

    Attributes:
        targets: target identifiers (domains, CIDRs, IPs, URLs).
        target_ids: stable target ids mapped positionally to ``targets``.
        criticality: per-target criticality in ``[0, 1]`` (positional).

    """

    targets: tuple[str, ...] = ()
    target_ids: tuple[str, ...] = ()
    criticality: tuple[float, ...] = ()

    def __post_init__(self) -> None:
        if self.target_ids and len(self.target_ids) != len(self.targets):
            raise ValueError("target_ids must be positional with targets")
        if self.criticality and len(self.criticality) != len(self.targets):
            raise ValueError("criticality must be positional with targets")

    def target_id(self, index: int) -> str:
        """Return the stable id for the target at ``index``."""
        if self.target_ids:
            return self.target_ids[index]
        return self.targets[index]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "targets": list(self.targets),
            "target_ids": list(self.target_ids),
            "criticality": list(self.criticality),
        }


@dataclass(frozen=True, slots=True)
class MissionStep:
    """A single planned step inside a phase.

    Attributes:
        step_id: stable step identifier.
        phase_id: owning phase identifier.
        action: logical action (e.g. ``recon.enumerate``) or tool id.
        capability: capability required to satisfy this step.
        target: target identifier the step acts upon.
        target_type: canonical target kind.
        parameters: step parameters.
        depends_on: ids of steps that must finish first.
        condition: condition expression (empty = unconditional).
        timeout_seconds: execution timeout.
        retryable: whether the step may be retried on transient failures.
        evidence_requirements: evidence kinds the step must produce.
        success_criteria: criteria that mark the step successful.
        tool_id: selected tool id (empty until selected).
        fallback_tools: ordered fallback tool ids.
        safety_class: safety class of the step.

    """

    step_id: str = field(default_factory=generate_id)
    phase_id: str = ""
    action: str = ""
    capability: str = ""
    target: str = ""
    target_type: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    condition: str = ""
    timeout_seconds: float = 60.0
    retryable: bool = True
    evidence_requirements: tuple[str, ...] = ()
    success_criteria: tuple[str, ...] = ()
    tool_id: str = ""
    fallback_tools: tuple[str, ...] = ()
    safety_class: str = "passive"
    state: TaskState = TaskState.PENDING

    def __post_init__(self) -> None:
        if not self.step_id:
            raise ValueError("step id must not be empty")
        if not self.phase_id:
            raise ValueError(f"step '{self.step_id}' must belong to a phase")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "step_id": self.step_id,
            "phase_id": self.phase_id,
            "action": self.action,
            "capability": self.capability,
            "target": self.target,
            "target_type": self.target_type,
            "parameters": dict(self.parameters),
            "depends_on": list(self.depends_on),
            "condition": self.condition,
            "timeout_seconds": self.timeout_seconds,
            "retryable": self.retryable,
            "evidence_requirements": list(self.evidence_requirements),
            "success_criteria": list(self.success_criteria),
            "tool_id": self.tool_id,
            "fallback_tools": list(self.fallback_tools),
            "safety_class": self.safety_class,
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class Phase:
    """A mission phase instance.

    Attributes:
        phase_id: identifier unique within the plan.
        kind: canonical :class:`MissionPhaseKind`.
        name: human-readable phase name.
        steps: steps owned by the phase.
        depends_on: ids of phases that must finish first.
        optional: ``True`` when the planner may skip the phase.
        parallel: whether the phase steps may run concurrently.

    """

    phase_id: str = field(default_factory=generate_id)
    kind: MissionPhaseKind = MissionPhaseKind.SCOPE
    name: str = ""
    steps: tuple[MissionStep, ...] = ()
    depends_on: tuple[str, ...] = ()
    optional: bool = False
    parallel: bool = False

    def __post_init__(self) -> None:
        if not self.phase_id:
            raise ValueError("phase id must not be empty")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "phase_id": self.phase_id,
            "kind": self.kind.value,
            "name": self.name,
            "steps": [step.to_dict() for step in self.steps],
            "depends_on": list(self.depends_on),
            "optional": self.optional,
            "parallel": self.parallel,
        }


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """A canonical execution plan produced by the mission planner.

    Attributes:
        plan_id: stable plan identifier.
        mission_id: owning mission.
        objective: mission objective the plan fulfils.
        phases: ordered phases (topologically sorted by dependencies).
        branch_conditions: conditional activation rules for phases.
        stop_conditions: conditions that stop execution.
        scope: the scope the plan is authorized for.
        policies: the policy envelope applied to this plan.
        version: plan version (incremented on replanning).

    """

    plan_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    objective: str = ""
    phases: tuple[Phase, ...] = ()
    branch_conditions: dict[str, str] = field(default_factory=dict)
    stop_conditions: tuple[str, ...] = ()
    scope: MissionScope = field(default_factory=MissionScope)
    policies: Policies = field(default_factory=Policies)
    version: int = 1
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)

    def phase(self, phase_id: str) -> Phase | None:
        """Return a phase by identifier or ``None``."""
        for phase in self.phases:
            if phase.phase_id == phase_id:
                return phase
        return None

    def step(self, step_id: str) -> MissionStep | None:
        """Return a step by identifier or ``None``."""
        for phase in self.phases:
            for step in phase.steps:
                if step.step_id == step_id:
                    return step
        return None

    def steps(self) -> tuple[MissionStep, ...]:
        """Return every step across all phases in plan order."""
        return tuple(step for phase in self.phases for step in phase.steps)

    def total_steps(self) -> int:
        """Return the number of steps in the plan."""
        return sum(len(phase.steps) for phase in self.phases)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "objective": self.objective,
            "phases": [phase.to_dict() for phase in self.phases],
            "branch_conditions": dict(self.branch_conditions),
            "stop_conditions": list(self.stop_conditions),
            "scope": self.scope.to_dict(),
            "policies": self.policies.to_dict(),
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(slots=True)
class OffensiveMission:
    """The canonical offensive mission object.

    This is the aggregate root of the orchestration layer: it carries the
    mission objective, scope, exclusions, authorization, priority, the full
    policy envelope, the target set and the runtime lifecycle state.

    Attributes:
        mission_id: stable mission identifier.
        mission_type: canonical :class:`MissionType`.
        objective: mission objective statement.
        scope: authorized :class:`MissionScope`.
        exclusions: explicit out-of-scope identifiers.
        authorization: :class:`Authorization` record.
        priority: ``low``/``medium``/``high``/``critical``.
        policies: :class:`Policies` envelope.
        target_set: :class:`TargetSet`.
        workflow: workflow reference.
        state: current :class:`MissionState`.
        plan_id: id of the current execution plan.
        analysis_version: analysis version producing this mission.
        created_at / started_at / completed_at: timestamps.

    """

    mission_id: str = field(default_factory=generate_id)
    mission_type: MissionType = MissionType.VULNERABILITY_ASSESSMENT
    objective: str = ""
    scope: MissionScope = field(default_factory=MissionScope)
    exclusions: tuple[str, ...] = ()
    authorization: Authorization = field(default_factory=Authorization)
    priority: str = "medium"
    policies: Policies = field(default_factory=Policies)
    target_set: TargetSet = field(default_factory=TargetSet)
    workflow: str = "offensive.orchestration"
    state: MissionState = MissionState.CREATED
    plan_id: str | None = None
    analysis_version: str = "1.0.0"
    created_at: str = field(default_factory=utcnow_iso)
    started_at: str | None = None
    completed_at: str | None = None
    updated_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return {
            "mission_id": self.mission_id,
            "mission_type": self.mission_type.value,
            "objective": self.objective,
            "scope": self.scope.to_dict(),
            "exclusions": list(self.exclusions),
            "authorization": {
                "reference": self.authorization.reference,
                "holder": self.authorization.holder,
                "status": self.authorization.status,
                "valid_until": self.authorization.valid_until,
                "note": self.authorization.note,
            },
            "priority": self.priority,
            "policies": self.policies.to_dict(),
            "target_set": self.target_set.to_dict(),
            "workflow": self.workflow,
            "state": self.state.value,
            "plan_id": self.plan_id,
            "analysis_version": self.analysis_version,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "updated_at": self.updated_at,
        }
