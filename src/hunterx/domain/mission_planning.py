# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission planning domain models.

Pure data contracts for the mission planning engine: mission types, phases,
profiles, templates, requests, plans, checkpoints, execution graphs and the
mission timeline. These models describe *how* an assessment is planned — no
tool is executed here. The planning engine reads and writes these structures.

The state machine, profile engine, configuration resolver, planner, graph
builder and checkpoint manager (``hunterx.engines.mission_planning``) drive
these models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.exceptions import (
    InvalidMissionPlanError,
    InvalidMissionRequestError,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class MissionType(Enum):
    """Supported mission (assessment) types.

    Mirrors the ratified profile catalog in ``docs/bible/12``.
    """

    BUG_BOUNTY = "bug-bounty"
    WEB_APPLICATION_PENTEST = "web-application-pentest"
    API_PENTEST = "api-pentest"
    EXTERNAL_PENTEST = "external-pentest"
    INTERNAL_PENTEST = "internal-pentest"
    RED_TEAM = "red-team"
    CLOUD_ASSESSMENT = "cloud-assessment"
    CONTAINER_ASSESSMENT = "container-assessment"
    KUBERNETES_ASSESSMENT = "kubernetes-assessment"
    ACTIVE_DIRECTORY_ASSESSMENT = "ad-assessment"
    NETWORK_ASSESSMENT = "network-assessment"
    MOBILE_ASSESSMENT = "mobile-assessment"
    CONTINUOUS_MONITORING = "continuous-monitoring"
    CUSTOM = "custom"


class MissionPhaseKind(Enum):
    """Canonical mission phases in execution order."""

    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    FINGERPRINTING = "fingerprinting"
    CRAWLING = "crawling"
    CONTENT_DISCOVERY = "content-discovery"
    PARAMETER_DISCOVERY = "parameter-discovery"
    TECHNOLOGY_ANALYSIS = "technology-analysis"
    VULNERABILITY_ASSESSMENT = "vulnerability-assessment"
    VALIDATION = "validation"
    CORRELATION = "correlation"
    RISK_ANALYSIS = "risk-analysis"
    REPORTING = "reporting"
    CLEANUP = "cleanup"


class MissionPlanningStatus(Enum):
    """Lifecycle states of a planned mission.

    Follows the ratified state machine: Created → Queued → Planning → Ready →
    Executing → (Paused / Waiting / Retrying) → Completed / Cancelled / Failed
    → Archived.
    """

    CREATED = "created"
    QUEUED = "queued"
    PLANNING = "planning"
    READY = "ready"
    EXECUTING = "executing"
    PAUSED = "paused"
    WAITING = "waiting"
    RETRYING = "retrying"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    ARCHIVED = "archived"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end a mission's lifecycle."""
        return self in (
            MissionPlanningStatus.COMPLETED,
            MissionPlanningStatus.CANCELLED,
            MissionPlanningStatus.FAILED,
            MissionPlanningStatus.ARCHIVED,
        )

    @property
    def is_active(self) -> bool:
        """Return ``True`` while the mission can still transition."""
        return not self.is_terminal


class MissionPhaseState(Enum):
    """Runtime state of a phase inside a mission plan."""

    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    BLOCKED = "blocked"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end a phase."""
        return self in (MissionPhaseState.COMPLETED, MissionPhaseState.SKIPPED, MissionPhaseState.FAILED)


class MissionApprovalLevel(Enum):
    """Human-approval requirement tier for a mission."""

    AUTO = "auto"
    OPERATOR = "operator"
    DESTRUCTIVE_APPROVAL = "destructive-approval"

    def requires_approval(self) -> bool:
        """Return ``True`` when a human approval gate is required."""
        return self is not MissionApprovalLevel.AUTO


@dataclass(frozen=True, slots=True)
class MissionPhase:
    """A phase definition in a mission profile.

    Attributes:
        phase_id: stable identifier unique within the profile.
        name: human-readable phase name.
        description: purpose of the phase.
        kind: canonical :class:`MissionPhaseKind`.
        optional: ``True`` when the planner may omit the phase.
        depends_on: ids of phases that must finish first.
        estimated_duration_seconds: planning estimate for the whole phase.
        actions: ordered tool/plugin action names the phase runs.
        expected_outputs: artifacts the phase is expected to produce.
        parallel: ``True`` when the phase may run in parallel with its siblings.
        approval_required: ``True`` when the phase needs explicit approval.
        variables: phase-scoped configuration defaults.

    """

    phase_id: str
    name: str
    kind: MissionPhaseKind
    description: str = ""
    optional: bool = False
    depends_on: tuple[str, ...] = ()
    estimated_duration_seconds: int = 0
    actions: tuple[str, ...] = ()
    expected_outputs: tuple[str, ...] = ()
    parallel: bool = False
    approval_required: bool = False
    variables: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.phase_id:
            raise InvalidMissionPlanError("phase id must not be empty.")
        if not self.name:
            raise InvalidMissionPlanError(f"phase '{self.phase_id}' name must not be empty.")
        if self.estimated_duration_seconds < 0:
            raise InvalidMissionPlanError(
                f"phase '{self.phase_id}' estimated duration must be non-negative."
            )
        if any(not dependency for dependency in self.depends_on):
            raise InvalidMissionPlanError(f"phase '{self.phase_id}' has an empty dependency id.")


@dataclass(frozen=True, slots=True)
class MissionProfile:
    """Declarative definition of a complete assessment type.

    Attributes:
        profile_id: stable identifier (e.g. ``external-pentest``).
        name: human-readable profile name.
        description: profile purpose.
        version: profile schema version (SemVer-style).
        mission_types: :class:`MissionType` values this profile supports.
        phases: ordered phase definitions.
        objectives: mission success criteria.
        allowed_tools: tool policy ``{"include": [...], "exclude": [...]}``.
        expected_outputs: output contract (report kinds, evidence rules).
        approval_level: :class:`MissionApprovalLevel`.
        risk_model: risk formula + weights + escalation mapping.
        constraints: time/concurrency/timeout budgets.
        compliance_map: report compliance targets.
        parent: profile id this profile inherits from (``None`` = built-in).

    """

    profile_id: str
    name: str
    description: str = ""
    version: str = "1.0.0"
    mission_types: tuple[MissionType, ...] = ()
    phases: tuple[MissionPhase, ...] = ()
    objectives: tuple[str, ...] = ()
    allowed_tools: dict[str, object] = field(default_factory=dict)
    expected_outputs: dict[str, object] = field(default_factory=dict)
    approval_level: MissionApprovalLevel = MissionApprovalLevel.OPERATOR
    risk_model: dict[str, object] = field(default_factory=dict)
    constraints: dict[str, object] = field(default_factory=dict)
    compliance_map: tuple[str, ...] = ()
    parent: str | None = None

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise InvalidMissionPlanError("profile id must not be empty.")
        if not self.name:
            raise InvalidMissionPlanError(f"profile '{self.profile_id}' name must not be empty.")
        if not self.phases:
            raise InvalidMissionPlanError(f"profile '{self.profile_id}' must declare at least one phase.")
        seen: set[str] = set()
        for phase in self.phases:
            if phase.phase_id in seen:
                raise InvalidMissionPlanError(
                    f"profile '{self.profile_id}' declares phase '{phase.phase_id}' twice."
                )
            seen.add(phase.phase_id)

    def phase(self, phase_id: str) -> MissionPhase | None:
        """Return a phase definition by id, or ``None``."""
        for phase in self.phases:
            if phase.phase_id == phase_id:
                return phase
        return None

    def supports(self, mission_type: MissionType) -> bool:
        """Return ``True`` when the profile supports ``mission_type``."""
        return not self.mission_types or mission_type in self.mission_types


@dataclass(frozen=True, slots=True)
class MissionTemplate:
    """A named, reusable mission configuration.

    Templates bind a profile to concrete variables, phase overrides and
    configuration. They let operators ship pre-configured mission recipes.

    Attributes:
        template_id: stable template identifier.
        name: human-readable template name.
        profile_id: the profile this template builds upon.
        description: template purpose.
        variables: default variable values (lowest precedence).
        phases_override: optional phase set replacing the profile's phases.
        config: mission-scoped configuration defaults.
        tags: searchable tags.

    """

    template_id: str
    name: str
    profile_id: str
    description: str = ""
    variables: dict[str, object] = field(default_factory=dict)
    phases_override: tuple[MissionPhase, ...] | None = None
    config: dict[str, object] = field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.template_id:
            raise InvalidMissionPlanError("template id must not be empty.")
        if not self.name:
            raise InvalidMissionPlanError(f"template '{self.template_id}' name must not be empty.")
        if not self.profile_id:
            raise InvalidMissionPlanError(f"template '{self.template_id}' must declare a profile id.")


@dataclass(frozen=True, slots=True)
class MissionRequest:
    """Input for planning a mission.

    Attributes:
        profile_id: profile to plan against.
        mission_type: :class:`MissionType` of the assessment.
        name: mission name.
        targets: authorized target identifiers.
        template_id: optional template to apply.
        variables: mission variables (highest precedence over template).
        config: mission-scoped configuration.
        priority: scheduling priority (``low``/``medium``/``high``/``critical``).

    """

    profile_id: str
    mission_type: MissionType
    name: str
    targets: tuple[str, ...] = ()
    template_id: str | None = None
    variables: dict[str, object] = field(default_factory=dict)
    config: dict[str, object] = field(default_factory=dict)
    priority: str = "medium"

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise InvalidMissionRequestError("mission profile id must not be empty.")
        if not self.name:
            raise InvalidMissionRequestError("mission name must not be empty.")
        if not self.targets:
            raise InvalidMissionRequestError("mission must declare at least one target.")


@dataclass(frozen=True, slots=True)
class PlanStep:
    """A single unit of planned work inside a phase.

    Attributes:
        step_id: stable step identifier within the plan.
        action: tool/plugin action to execute.
        target: target identifier.
        parameters: action parameters.
        phase_id: owning planned phase id.
        depends_on: ids of steps that must finish first.
        estimated_duration_seconds: planning estimate.
        approval_required: ``True`` when the step needs explicit approval.

    """

    step_id: str
    action: str
    target: str
    parameters: dict[str, object] = field(default_factory=dict)
    phase_id: str = ""
    depends_on: tuple[str, ...] = ()
    estimated_duration_seconds: int = 0
    approval_required: bool = False

    def __post_init__(self) -> None:
        if not self.step_id:
            raise InvalidMissionPlanError("step id must not be empty.")
        if not self.action:
            raise InvalidMissionPlanError(f"step '{self.step_id}' must declare an action.")


@dataclass(frozen=True, slots=True)
class PlannedPhase:
    """A phase instance within a mission plan.

    Attributes:
        phase_id: identifier unique within the plan.
        kind: canonical :class:`MissionPhaseKind`.
        name: human-readable phase name.
        status: runtime :class:`MissionPhaseState`.
        optional: ``True`` when the planner may skip the phase.
        depends_on: ids of planned phases that must finish first.
        estimated_duration_seconds: summed planning estimate.
        steps: planned steps owned by the phase.
        expected_outputs: artifacts the phase is expected to produce.
        approval_required: ``True`` when the phase needs explicit approval.
        started_at / completed_at: UTC ISO-8601 timestamps.

    """

    phase_id: str
    kind: MissionPhaseKind
    name: str
    status: MissionPhaseState = MissionPhaseState.PENDING
    optional: bool = False
    depends_on: tuple[str, ...] = ()
    estimated_duration_seconds: int = 0
    steps: tuple[PlanStep, ...] = ()
    expected_outputs: tuple[str, ...] = ()
    approval_required: bool = False
    parallel: bool = False
    started_at: str | None = None
    completed_at: str | None = None

    def __post_init__(self) -> None:
        if not self.phase_id:
            raise InvalidMissionPlanError("planned phase id must not be empty.")

    @property
    def is_done(self) -> bool:
        """Return ``True`` when the phase finished (any terminal state)."""
        return self.status.is_terminal


@dataclass(slots=True)
class MissionPlan:
    """A concrete execution plan for a mission.

    The planning aggregate. Produced by the planner, advanced by the state
    machine, snapshotted by checkpoints and recorded on the timeline.

    Attributes:
        plan_id: stable plan identifier.
        mission_id: owning mission identifier.
        profile_id: profile the plan was built from.
        template_id: optional template used.
        mission_type: :class:`MissionType` of the assessment.
        name: mission name.
        status: lifecycle :class:`MissionPlanningStatus`.
        phases: planned phases in dependency order.
        targets: authorized target identifiers.
        variables: resolved mission variables.
        config: resolved mission configuration.
        priority: scheduling priority.
        approval_level: :class:`MissionApprovalLevel`.
        progress: completion percentage in ``[0, 100]``.
        estimated_duration_seconds: summed phase estimates.
        created_at / updated_at / started_at / completed_at: timestamps.

    """

    plan_id: str = field(default_factory=generate_id)
    mission_id: str = field(default_factory=generate_id)
    profile_id: str = ""
    template_id: str | None = None
    mission_type: MissionType = MissionType.CUSTOM
    name: str = ""
    status: MissionPlanningStatus = MissionPlanningStatus.CREATED
    phases: tuple[PlannedPhase, ...] = ()
    targets: tuple[str, ...] = ()
    variables: dict[str, object] = field(default_factory=dict)
    config: dict[str, object] = field(default_factory=dict)
    priority: str = "medium"
    approval_level: MissionApprovalLevel = MissionApprovalLevel.OPERATOR
    progress: float = 0.0
    estimated_duration_seconds: int = 0
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str = field(default_factory=utcnow_iso)
    started_at: str | None = None
    completed_at: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise InvalidMissionPlanError("mission plan name must not be empty.")
        if not 0.0 <= self.progress <= 100.0:
            raise InvalidMissionPlanError("plan progress must be in [0, 100].")
        seen: set[str] = set()
        for phase in self.phases:
            if phase.phase_id in seen:
                raise InvalidMissionPlanError(f"plan declares phase '{phase.phase_id}' twice.")
            seen.add(phase.phase_id)

    def phase(self, phase_id: str) -> PlannedPhase | None:
        """Return a planned phase by id, or ``None``."""
        for phase in self.phases:
            if phase.phase_id == phase_id:
                return phase
        return None

    def step(self, step_id: str) -> PlanStep | None:
        """Return a planned step by id across all phases, or ``None``."""
        for phase in self.phases:
            for step in phase.steps:
                if step.step_id == step_id:
                    return step
        return None

    @property
    def total_steps(self) -> int:
        """Return the number of planned steps."""
        return sum(len(phase.steps) for phase in self.phases)

    @property
    def completed_steps(self) -> int:
        """Return the number of completed steps."""
        total = 0
        for phase in self.phases:
            if phase.status is MissionPhaseState.COMPLETED:
                total += len(phase.steps)
        return total

    def update_progress(self, progress: float) -> None:
        """Update completion progress in ``[0, 100]`` and the updated timestamp."""
        if not 0.0 <= progress <= 100.0:
            raise InvalidMissionPlanError("progress must be in [0, 100].")
        self.progress = progress
        self.updated_at = utcnow_iso()

    def to_dict(self) -> dict[str, object]:
        """Serialize the plan to a JSON-safe mapping."""
        return {
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "profile_id": self.profile_id,
            "template_id": self.template_id,
            "mission_type": self.mission_type.value,
            "name": self.name,
            "status": self.status.value,
            "progress": self.progress,
            "priority": self.priority,
            "approval_level": self.approval_level.value,
            "targets": list(self.targets),
            "variables": self.variables,
            "config": self.config,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A point-in-time snapshot of a mission plan for recovery and rerun.

    Attributes:
        checkpoint_id: stable checkpoint identifier.
        plan_id: owning plan identifier.
        mission_id: owning mission identifier.
        label: human-readable checkpoint name.
        snapshot: JSON-safe plan state (completed phases, steps, variables).
        rerun_from: optional step id to restart a partial rerun from.
        created_at: UTC ISO-8601 timestamp.

    """

    checkpoint_id: str = field(default_factory=generate_id)
    plan_id: str = ""
    mission_id: str = ""
    label: str = ""
    snapshot: dict[str, object] = field(default_factory=dict)
    rerun_from: str | None = None
    created_at: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if not self.plan_id:
            raise InvalidMissionPlanError("checkpoint must reference a plan id.")
        if not self.label:
            raise InvalidMissionPlanError("checkpoint label must not be empty.")

    def to_dict(self) -> dict[str, object]:
        """Serialize the checkpoint to a JSON-safe mapping."""
        return {
            "checkpoint_id": self.checkpoint_id,
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "label": self.label,
            "rerun_from": self.rerun_from,
            "snapshot": self.snapshot,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class MissionTimelineEntry:
    """A single fact recorded on a mission's timeline.

    Attributes:
        entry_id: stable entry identifier.
        mission_id: owning mission identifier.
        plan_id: optional owning plan identifier.
        event_type: stable machine name (e.g. ``mission.queued``).
        payload: JSON-safe event data.
        source: originating component.
        occurred_at: UTC ISO-8601 timestamp.

    """

    entry_id: str = field(default_factory=generate_id)
    mission_id: str = ""
    plan_id: str | None = None
    event_type: str = ""
    payload: dict[str, object] = field(default_factory=dict)
    source: str = "mission.planning"
    occurred_at: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        if not self.mission_id:
            raise InvalidMissionPlanError("timeline entry must reference a mission id.")
        if not self.event_type:
            raise InvalidMissionPlanError("timeline entry event type must not be empty.")

    def to_dict(self) -> dict[str, object]:
        """Serialize the entry to a JSON-safe mapping."""
        return {
            "entry_id": self.entry_id,
            "mission_id": self.mission_id,
            "plan_id": self.plan_id,
            "event_type": self.event_type,
            "payload": self.payload,
            "source": self.source,
            "occurred_at": self.occurred_at,
        }


@dataclass(frozen=True, slots=True)
class ExecutionNode:
    """A single node in a mission's execution graph (DAG).

    Attributes:
        node_id: stable node identifier.
        action: tool/plugin action to execute.
        target: target identifier.
        parameters: action parameters.
        phase_id: owning planned phase id.
        phase_kind: canonical phase kind.
        depends_on: ids of nodes that must finish first.
        parallel: ``True`` when the node may run concurrently with siblings.
        conditional: ``True`` when ``condition`` gates execution.
        condition: expression evaluated before execution (empty = unconditional).
        fallback_node_id: node to run when this node fails.
        retryable: ``True`` when a failed node may be retried.
        approval_required: ``True`` when the node needs explicit approval.
        estimated_duration_seconds: planning estimate.

    """

    node_id: str
    action: str
    target: str
    parameters: dict[str, object] = field(default_factory=dict)
    phase_id: str = ""
    phase_kind: MissionPhaseKind = MissionPhaseKind.PLANNING
    depends_on: tuple[str, ...] = ()
    parallel: bool = False
    conditional: bool = False
    condition: str = ""
    fallback_node_id: str | None = None
    retryable: bool = False
    approval_required: bool = False
    estimated_duration_seconds: int = 0

    def __post_init__(self) -> None:
        if not self.node_id:
            raise InvalidMissionPlanError("node id must not be empty.")
        if not self.action:
            raise InvalidMissionPlanError(f"node '{self.node_id}' must declare an action.")

    def to_dict(self) -> dict[str, object]:
        """Serialize the node to a JSON-safe mapping."""
        return {
            "node_id": self.node_id,
            "action": self.action,
            "target": self.target,
            "parameters": self.parameters,
            "phase_id": self.phase_id,
            "phase_kind": self.phase_kind.value,
            "depends_on": list(self.depends_on),
            "parallel": self.parallel,
            "conditional": self.conditional,
            "condition": self.condition,
            "fallback_node_id": self.fallback_node_id,
            "retryable": self.retryable,
            "approval_required": self.approval_required,
            "estimated_duration_seconds": self.estimated_duration_seconds,
        }


@dataclass(frozen=True, slots=True)
class ExecutionGraph:
    """A directed acyclic graph of execution nodes.

    Attributes:
        nodes: all graph nodes.
        root_ids: ids of nodes with no dependencies (entry points).

    """

    nodes: tuple[ExecutionNode, ...]
    root_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        errors = self.validate()
        if errors:
            raise InvalidMissionPlanError("invalid execution graph: " + "; ".join(errors))

    def node(self, node_id: str) -> ExecutionNode | None:
        """Return a node by id, or ``None``."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None

    def validate(self) -> list[str]:
        """Return structural errors (empty when the graph is a valid DAG).

        Checks for duplicate ids, unknown dependencies and dependency cycles.
        """
        errors: list[str] = []
        known = {node.node_id for node in self.nodes}
        if not self.nodes:
            errors.append("execution graph has no nodes")
        seen: set[str] = set()
        for node in self.nodes:
            if node.node_id in seen:
                errors.append(f"node '{node.node_id}' is declared more than once")
            seen.add(node.node_id)
            for dependency in node.depends_on:
                if dependency not in known:
                    errors.append(f"node '{node.node_id}' depends on unknown node '{dependency}'")
        if self.nodes and len(self.topological_order()) != len(self.nodes):
            errors.append("execution graph contains a dependency cycle")
        return errors

    def topological_order(self) -> list[str]:
        """Return node ids in dependency order (Kahn's algorithm).

        Parallel-sibling nodes keep their declaration order; the returned order
        is a valid execution sequence that honors every ``depends_on`` edge.
        """
        order: list[str] = []
        remaining = {node.node_id: set(node.depends_on) for node in self.nodes}
        ready = [node_id for node_id, deps in remaining.items() if not deps]
        while ready:
            node_id = ready.pop(0)
            order.append(node_id)
            for candidate, deps in remaining.items():
                if node_id in deps:
                    deps.discard(node_id)
                    if not deps and candidate not in order:
                        ready.append(candidate)
        return order

    def parallel_groups(self) -> list[list[str]]:
        """Return node ids grouped into waves of concurrently runnable nodes."""
        groups: list[list[str]] = []
        completed: set[str] = set()
        remaining = {node.node_id: set(node.depends_on) for node in self.nodes}
        while True:
            wave = [nid for nid, deps in remaining.items() if not deps and nid not in completed]
            if not wave:
                break
            groups.append(wave)
            completed.update(wave)
            for deps in remaining.values():
                deps.difference_update(wave)
        return groups

    def successors(self, node_id: str) -> list[str]:
        """Return ids of nodes that depend directly on ``node_id``."""
        return [node.node_id for node in self.nodes if node_id in node.depends_on]

    def rollback_scope(self, node_id: str) -> list[str]:
        """Return node ids invalidated when ``node_id`` fails (its closure)."""
        scope: set[str] = set()
        pending = list(self.successors(node_id))
        while pending:
            current = pending.pop(0)
            if current in scope:
                continue
            scope.add(current)
            pending.extend(self.successors(current))
        return [node_id, *sorted(scope)]

    def recovery_path(self, failed_node_id: str) -> list[str]:
        """Return node ids to retry after ``failed_node_id`` recovers.

        Includes the failed node and every dependant that must rerun.
        """
        return self.rollback_scope(failed_node_id)

    def total_duration_seconds(self) -> int:
        """Return the critical-path duration estimate of the graph."""
        duration: dict[str, int] = {}
        for node_id in self.topological_order():
            node = self.node(node_id)
            assert node is not None  # nosec B101  # topological order yields existing nodes
            base = 0
            if node.depends_on:
                base = max(duration.get(dep, 0) for dep in node.depends_on)
            duration[node_id] = base + node.estimated_duration_seconds
        return max(duration.values(), default=0)

    def nodes_in_phase(self, phase_id: str) -> list[ExecutionNode]:
        """Return nodes belonging to ``phase_id``."""
        return [node for node in self.nodes if node.phase_id == phase_id]
