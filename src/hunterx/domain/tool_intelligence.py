# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform — domain models.

Pure data models for the intelligence layer that understands, evaluates,
orchestrates and optimizes security tools. No I/O, no adapters, no execution —
these are the structured contracts that every TIP subsystem reads and writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolState(Enum):
    """Lifecycle states of a tool as managed by the state machine.

    States follow the ratified order: registered → installed → verified →
    available → running → completed | failed, with deprecated and disabled as
    terminal/modifier states.
    """

    REGISTERED = "registered"
    INSTALLED = "installed"
    VERIFIED = "verified"
    AVAILABLE = "available"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DEPRECATED = "deprecated"
    DISABLED = "disabled"


class ToolExecutionType(Enum):
    """How a tool is packaged and launched."""

    BINARY = "binary"
    PIP = "pip"
    DOCKER = "docker"
    PLUGIN = "plugin"
    SYSTEM = "system"
    REMOTE = "remote"


class MaintenanceStatus(Enum):
    """Upstream maintenance status of a tool project."""

    ACTIVE = "active"
    MAINTAINED = "maintained"
    UNMAINTAINED = "unmaintained"
    ARCHIVED = "archived"
    ABANDONED = "abandoned"


class ProjectActivity(Enum):
    """Commit/release activity of a tool project."""

    VERY_HIGH = "very-high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INACTIVE = "inactive"


class RecommendationKind(Enum):
    """Kinds of tool recommendations produced by the recommendation engine."""

    BEST = "best"
    ALTERNATIVE = "alternative"
    FALLBACK = "fallback"
    COMPLEMENTARY = "complementary"
    REPLACEMENT = "replacement"
    DEPRECATED = "deprecated"


@dataclass(frozen=True, slots=True)
class ToolMetadata:
    """Rich metadata for a registered tool.

    Attributes:
        tool_id: unique identifier (``[a-z0-9-]+``).
        display_name: human-readable name.
        vendor: organization/author that publishes the tool.
        project_url: canonical project homepage.
        license: SPDX license identifier.
        category: taxonomy category (e.g. ``recon``).
        subcategory: taxonomy subcategory (e.g. ``dns``).
        version: latest known upstream version.
        platforms: supported operating systems.
        architectures: supported CPU architectures.
        language: primary implementation language.
        execution_type: how the tool is launched.
        package_manager: package manager / distribution channel.
        container_available: a container image is published.
        binary_available: prebuilt binaries are published.
        maintenance_status: upstream maintenance health.
        project_activity: upstream commit/release activity.
        community_score: community adoption score in ``[0, 100]``.
        description: one-line summary.
        tags: search tags.

    """

    tool_id: str
    display_name: str = ""
    vendor: str = ""
    project_url: str = ""
    license: str = ""
    category: str = ""
    subcategory: str = ""
    version: str = ""
    platforms: tuple[str, ...] = ()
    architectures: tuple[str, ...] = ()
    language: str = ""
    execution_type: ToolExecutionType = ToolExecutionType.BINARY
    package_manager: str = ""
    container_available: bool = False
    binary_available: bool = False
    maintenance_status: MaintenanceStatus = MaintenanceStatus.ACTIVE
    project_activity: ProjectActivity = ProjectActivity.MEDIUM
    community_score: float = 0.0
    description: str = ""
    tags: tuple[str, ...] = ()

    def __str__(self) -> str:
        return f"{self.tool_id}@{self.version}"


@dataclass(frozen=True, slots=True)
class ToolArgument:
    """A single CLI/configuration argument a tool accepts.

    Attributes:
        name: canonical argument name.
        flag: CLI flag spelling (e.g. ``-u``).
        kind: value kind (``string``, ``int``, ``bool``, ``choice``, ``list``).
        required: whether the argument is mandatory.
        default: default value when omitted.
        description: human-readable meaning.
        choices: allowed values for ``kind == "choice"``.

    """

    name: str
    flag: str = ""
    kind: str = "string"
    required: bool = False
    default: Any = None
    description: str = ""
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolExecutionMode:
    """A named execution mode with a safety posture.

    Attributes:
        id: stable mode identifier (e.g. ``fast``, ``thorough``).
        description: what the mode does.
        safe: runs within safe, non-destructive bounds.
        aggressive: may push limits and requires higher approval.
        args: default argument list for the mode.

    """

    id: str
    description: str = ""
    safe: bool = True
    aggressive: bool = False
    args: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolInputContract:
    """The inputs a tool consumes.

    Attributes:
        accepts: canonical input types (``url``, ``domain``, ``host``, ...).
        required: input types that must be present.
        optional: input types that may be provided.
        transforms: preprocessing transforms to apply.
        max_targets_per_invocation: batch bound (``0`` = unlimited).

    """

    accepts: tuple[str, ...] = ()
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    transforms: tuple[str, ...] = ()
    max_targets_per_invocation: int = 0


@dataclass(frozen=True, slots=True)
class ToolOutputContract:
    """The outputs a tool produces and how to interpret them.

    Attributes:
        formats: supported output formats.
        parser: id of the output parser.
        normalizer: id of the normalizer.
        event_types: canonical events the tool can emit.
        evidence_capture: evidence fields that can be captured.
        dedup_key_spec: fields used to derive the finding dedup hash.

    """

    formats: tuple[str, ...] = ()
    parser: str = ""
    normalizer: str = ""
    event_types: tuple[str, ...] = ()
    evidence_capture: tuple[str, ...] = ()
    dedup_key_spec: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolDependency:
    """A capability dependency between tools.

    Attributes:
        capability: capability id the tool requires.
        provided_by: tool id that provides the capability (empty = any).
        optional: dependency may be skipped.
        description: explanation of the dependency.

    """

    capability: str
    provided_by: str = ""
    optional: bool = False
    description: str = ""


@dataclass(frozen=True, slots=True)
class ToolKnowledge:
    """Structured knowledge profile for a tool.

    This is the machine-readable contract the Planner, AI Engine and
    Documentation Generator consume. Mirrors
    ``docs/bible/07 - Tool Knowledge Base Specification.md`` and is extended
    by Sprint 023 with the invocation, safety, scope, resource, evidence and
    proof contracts that drive the Tool Intelligence Layer.
    """

    tool_id: str
    canonical_name: str = ""
    purpose: str = ""
    capabilities: tuple[str, ...] = ()
    supported_assessments: tuple[str, ...] = ()
    supported_mission_profiles: tuple[str, ...] = ()
    inputs: ToolInputContract = field(default_factory=ToolInputContract)
    outputs: ToolOutputContract = field(default_factory=ToolOutputContract)
    cli_binary: str = ""
    cli_structure: str = ""
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    safe_mode: str = ""
    aggressive_mode: str = ""
    authentication_requirements: str = ""
    privileges_required: str = ""
    limitations: tuple[str, ...] = ()
    known_issues: tuple[str, ...] = ()
    performance_notes: str = ""
    installation_requirements: tuple[str, ...] = ()
    dependencies: tuple[ToolDependency, ...] = ()
    alternative_tools: tuple[str, ...] = ()
    recommended_usage: tuple[str, ...] = ()
    common_mistakes: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    # -- Sprint 023 Tool Intelligence Layer extensions ---------------------
    supported_targets: tuple[str, ...] = ()
    supported_protocols: tuple[str, ...] = ()
    supported_vulnerabilities: tuple[str, ...] = ()
    supported_evidence_types: tuple[str, ...] = ()
    supported_proof_strategies: tuple[str, ...] = ()
    input_schema: ToolInputSchema | None = None
    output_schema: ToolOutputSchema | None = None
    invocation_contract: ToolInvocationContract | None = None
    configuration_contract: str = ""
    resource_requirements: ToolResourceRequirements | None = None
    safety_profile: ToolSafetyProfile | None = None
    scope_profile: ToolScopeProfile | None = None
    parser_id: str = ""
    normalizer_id: str = ""
    adapter_id: str = ""
    version_constraints: tuple[str, ...] = ()
    known_false_positives: tuple[str, ...] = ()
    known_false_negatives: tuple[str, ...] = ()
    provenance: dict[str, str] = field(default_factory=dict)
    knowledge_version: str = "1.0.0"


@dataclass(frozen=True, slots=True)
class ToolCapability:
    """A discrete, searchable capability a tool can provide.

    Attributes:
        capability_id: stable capability id (e.g. ``subdomain-discovery``).
        name: short name.
        category: taxonomy category.
        subcategory: taxonomy subcategory.
        description: what the capability does.
        techniques: related MITRE-style techniques.
        missions: mission profiles that need this capability.
        required_inputs: canonical input types the capability consumes.
        produced_outputs: canonical output types the capability produces.
        risk_level: baseline risk of exercising the capability
            (``passive``, ``low``, ``active``, ``high``).
        supported_targets: target kinds the capability applies to.
        required_permissions: permission flags needed to exercise it.
        supported_proof_types: proof types the capability can support.

    """

    capability_id: str
    name: str = ""
    category: str = ""
    subcategory: str = ""
    description: str = ""
    techniques: tuple[str, ...] = ()
    missions: tuple[str, ...] = ()
    required_inputs: tuple[str, ...] = ()
    produced_outputs: tuple[str, ...] = ()
    risk_level: str = "passive"
    supported_targets: tuple[str, ...] = ()
    required_permissions: tuple[str, ...] = ()
    supported_proof_types: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolCompatibility:
    """Execution-environment compatibility of a tool.

    Attributes:
        tool_id: the tool this profile belongs to.
        os: compatible operating systems.
        architectures: compatible CPU architectures.
        python_versions: compatible Python versions (for pip/plugin tools).
        docker: runnable via Docker.
        containerized: designed for containerized execution.
        native: runnable as a native binary.
        cloud: runnable from cloud execution environments.
        air_gapped: usable without internet access.

    """

    tool_id: str = ""
    os: tuple[str, ...] = ()
    architectures: tuple[str, ...] = ()
    python_versions: tuple[str, ...] = ()
    docker: bool = False
    containerized: bool = False
    native: bool = True
    cloud: bool = False
    air_gapped: bool = True


@dataclass(slots=True)
class ToolRuntimeState:
    """Per-tool runtime lifecycle state.

    Attributes:
        tool_id: the tool this state belongs to.
        state: current lifecycle state.
        installed_version: installed version (empty when not installed).
        installed_at: ISO-8601 install timestamp.
        last_verified_at: ISO-8601 last successful verification.
        last_error: last lifecycle error message.

    """

    tool_id: str
    state: ToolState = ToolState.REGISTERED
    installed_version: str = ""
    installed_at: str = ""
    last_verified_at: str = ""
    last_error: str = ""


@dataclass(slots=True)
class ToolHealthStats:
    """Live health observations for a tool.

    Attributes:
        tool_id: the tool these stats belong to.
        availability: whether the tool is currently usable.
        execution_failures: total recorded execution failures.
        crash_frequency: crashes per recent sample window.
        average_runtime_ms: mean runtime over recorded runs.
        memory_usage_mb: typical resident memory in MB.
        cpu_usage_pct: typical CPU utilization percentage.
        timeouts: total recorded timeouts.
        reliability_score: computed reliability in ``[0, 1]``.
        samples: number of recorded samples.

    """

    tool_id: str
    availability: bool = True
    execution_failures: int = 0
    crash_frequency: float = 0.0
    average_runtime_ms: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_pct: float = 0.0
    timeouts: int = 0
    reliability_score: float = 1.0
    samples: int = 0


@dataclass(slots=True)
class ToolPerformanceStats:
    """Historical performance statistics for a tool.

    Attributes:
        tool_id: the tool these stats belong to.
        average_duration_ms: mean execution duration.
        average_findings: mean number of findings per run.
        success_rate: fraction of runs that succeeded.
        false_positive_rate: fraction of findings later refuted.
        failure_rate: fraction of runs that failed.
        execution_cost: average cost per execution.
        samples: number of recorded samples.

    """

    tool_id: str
    average_duration_ms: float = 0.0
    average_findings: float = 0.0
    success_rate: float = 1.0
    false_positive_rate: float = 0.0
    failure_rate: float = 0.0
    execution_cost: float = 0.0
    samples: int = 0


@dataclass(frozen=True, slots=True)
class ToolRecommendation:
    """A recommendation produced for a capability need.

    Attributes:
        tool_id: recommended tool.
        kind: :class:`RecommendationKind`.
        score: recommendation score in ``[0, 1]``.
        reason: human-readable justification.

    """

    tool_id: str
    kind: RecommendationKind = RecommendationKind.BEST
    score: float = 0.0
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ToolSelectionCriteria:
    """Criteria used by the selection engine to rank candidate tools.

    Attributes:
        mission_profile: mission profile name.
        target_type: target kind being assessed.
        available_inputs: input types already available.
        required_capabilities: capabilities the mission needs.
        max_execution_time_s: maximum acceptable runtime (``0`` = none).
        require_installed: only consider installed tools.
        os: target operating system.
        architecture: target CPU architecture.
        air_gapped: execution must not need internet.
        cloud: execution runs in the cloud.
        preferences: user-preferred tool ids.
        limit: maximum number of results.

    """

    mission_profile: str = ""
    target_type: str = ""
    available_inputs: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    max_execution_time_s: float = 0.0
    require_installed: bool = True
    os: str = ""
    architecture: str = ""
    air_gapped: bool = False
    cloud: bool = False
    preferences: tuple[str, ...] = ()
    limit: int = 10


@dataclass(frozen=True, slots=True)
class ToolSelectionResult:
    """A ranked selection candidate.

    Attributes:
        tool_id: candidate tool.
        score: selection score in ``[0, 1]``.
        reasons: reasons contributing to the score.

    """

    tool_id: str
    score: float
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolTaxonomyNode:
    """A node in the tool taxonomy hierarchy.

    Attributes:
        id: stable node identifier.
        name: display name.
        kind: node kind (``category``, ``subcategory``, ``capability``, ``technique``, ``mission``).
        children: child nodes.

    """

    id: str
    name: str
    kind: str = "category"
    children: tuple[ToolTaxonomyNode, ...] = ()

    def find(self, node_id: str) -> ToolTaxonomyNode | None:
        """Return a descendant node by identifier, or ``None``."""
        if self.id == node_id:
            return self
        for child in self.children:
            found = child.find(node_id)
            if found is not None:
                return found
        return None


# ==========================================================================
# Sprint 023 — Tool Intelligence & Capability Knowledge Layer
#
# The following contracts extend the TIP with the invocation, safety, scope,
# resource, evidence and proof knowledge that let HunterX understand WHAT a
# tool does, WHEN/WHY to use it and HOW to execute, parse, normalize and
# evaluate its results — without ever constructing raw shell commands.
# ==========================================================================


class ToolSafetyClass(Enum):
    """Impact class of a tool, used for safety ceilings.

    The ToolSelector must never select a tool whose safety class exceeds the
    mission/target authorization. Ordering is meaningful for ceilings.
    """

    PASSIVE = "passive"
    LOW_IMPACT_ACTIVE = "low-impact-active"
    ACTIVE = "active"
    HIGH_IMPACT = "high-impact"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        """Return the escalation rank used for ceiling comparisons."""
        return {
            ToolSafetyClass.PASSIVE: 0,
            ToolSafetyClass.LOW_IMPACT_ACTIVE: 1,
            ToolSafetyClass.ACTIVE: 2,
            ToolSafetyClass.HIGH_IMPACT: 3,
            ToolSafetyClass.RESTRICTED: 4,
        }[self]

    def exceeds(self, other: ToolSafetyClass) -> bool:
        """Return ``True`` when this class is riskier than ``other``."""
        return self.rank > other.rank


class ToolAvailabilityStatus(Enum):
    """Reported availability of a tool capability.

    The system reports ``CAPABILITY_UNAVAILABLE`` instead of pretending an
    execution occurred when a capability cannot be satisfied.
    """

    INSTALLED = "installed"
    MISSING = "missing"
    DISABLED = "disabled"
    UNSUPPORTED_PLATFORM = "unsupported-platform"
    UNSUPPORTED_VERSION = "unsupported-version"
    BROKEN_DEPENDENCY = "broken-dependency"
    PERMISSION_DENIED = "permission-denied"
    RUNTIME_UNAVAILABLE = "runtime-unavailable"


class ObservationKind(Enum):
    """Canonical observation kinds produced by tool parsers/normalizers."""

    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    PORT = "port"
    PROTOCOL = "protocol"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    VERSION = "version"
    HEADER = "header"
    PARAMETER = "parameter"
    PATH = "path"
    CLOUD_RESOURCE = "cloud-resource"
    VULNERABILITY = "vulnerability"
    CVE = "cve"
    CWE = "cwe"
    ASSET = "asset"
    CERTIFICATE = "certificate"
    TIMESTAMP = "timestamp"
    EVIDENCE = "evidence"
    OTHER = "other"


class EvidenceStrength(Enum):
    """How much a tool observation supports proof.

    Passive scanners produce detection evidence; active validators produce
    behavioral evidence; proof-capable tools produce proof evidence.
    """

    DETECTION = "detection"
    BEHAVIORAL = "behavioral"
    PROOF = "proof"


class ToolChainCondition(Enum):
    """Conditional routing hooks for tool-chain steps."""

    ON_SUCCESS = "on-success"
    ON_FAILURE = "on-failure"
    ON_FINDING = "on-finding"
    ON_EVIDENCE = "on-evidence"
    ON_CONFIDENCE = "on-confidence"
    ON_ASSET_DISCOVERED = "on-asset-discovered"
    ON_PROOF_REQUIRED = "on-proof-required"
    ON_SCOPE_CHANGE = "on-scope-change"
    ON_TARGET_CHANGE = "on-target-change"


class ChainStepState(Enum):
    """Lifecycle state of a tool-chain step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ChainStatus(Enum):
    """Lifecycle state of a tool chain."""

    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    STOPPED = "stopped"
    ABORTED = "aborted"


class EscalationLevel(Enum):
    """Escalation ladder: passive observation → proof."""

    PASSIVE_OBSERVATION = "passive-observation"
    ACTIVE_VALIDATION = "active-validation"
    DEEP_VALIDATION = "deep-validation"
    PROOF = "proof"

    @property
    def rank(self) -> int:
        """Return the escalation rank."""
        return {
            EscalationLevel.PASSIVE_OBSERVATION: 0,
            EscalationLevel.ACTIVE_VALIDATION: 1,
            EscalationLevel.DEEP_VALIDATION: 2,
            EscalationLevel.PROOF: 3,
        }[self]


@dataclass(frozen=True, slots=True)
class ToolInputField:
    """A single typed input of a tool's input schema.

    Attributes:
        name: canonical parameter name.
        kind: value kind (``string``, ``int``, ``float``, ``bool``, ``choice``,
            ``list``, ``path``, ``url``, ``domain``, ``ip``, ``host``, ``port``).
        required: the field must be present before execution.
        default: default value when omitted.
        choices: allowed values for ``kind == "choice"``.
        pattern: optional regex constraint.
        description: human-readable meaning.
        sensitive: value must be redacted in logs/artifacts.
        scope_linked: value must stay inside the authorized scope.

    """

    name: str
    kind: str = "string"
    required: bool = False
    default: Any = None
    choices: tuple[str, ...] = ()
    pattern: str = ""
    description: str = ""
    sensitive: bool = False
    scope_linked: bool = False


@dataclass(frozen=True, slots=True)
class ToolInputSchema:
    """Typed input contract validated before execution.

    Invalid input MUST fail before execution — never inside the tool.

    Attributes:
        fields: declared input fields.
        required: input fields that must be provided.
        optional: input fields that may be provided.
        target_type: canonical target kind (``host``, ``domain``, ``url``...).
        scope: scope reference/requirement for the inputs.
        authentication: authentication context requirements.
        headers: allowed header keys.
        cookies: allowed cookie names.
        rate_limits: canonical rate-limit hints.
        timeout: default timeout in seconds.
        output_format: preferred output format.
        execution_mode: permitted execution mode.

    """

    fields: tuple[ToolInputField, ...] = ()
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    target_type: str = ""
    scope: str = ""
    authentication: str = ""
    headers: tuple[str, ...] = ()
    cookies: tuple[str, ...] = ()
    rate_limits: tuple[str, ...] = ()
    timeout: float = 0.0
    output_format: str = ""
    execution_mode: str = ""

    def field(self, name: str) -> ToolInputField | None:
        """Return the field with ``name`` or ``None``."""
        for item in self.fields:
            if item.name == name:
                return item
        return None


@dataclass(frozen=True, slots=True)
class ToolOutputField:
    """A single typed output of a tool's output schema.

    Attributes:
        name: canonical field name.
        kind: value kind.
        description: meaning of the field.
        required: the field must be present in validated output.

    """

    name: str
    kind: str = "string"
    description: str = ""
    required: bool = False


@dataclass(frozen=True, slots=True)
class ToolOutputSchema:
    """Typed output contract the parser must validate against.

    Attributes:
        fields: declared output fields.
        required_fields: fields that must be present in parsed output.
        formats: supported output formats (``json``, ``jsonl``, ``xml``...).

    """

    fields: tuple[ToolOutputField, ...] = ()
    required_fields: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()

    def field(self, name: str) -> ToolOutputField | None:
        """Return the field with ``name`` or ``None``."""
        for item in self.fields:
            if item.name == name:
                return item
        return None


@dataclass(frozen=True, slots=True)
class ToolInvocationContract:
    """Structured, non-raw invocation contract for a tool.

    The contract is the ONLY way to launch a tool. Arguments are typed
    structured values — never concatenated strings from AI-generated input.

    Attributes:
        command: executable identifier (never interpolated with arguments).
        arguments: typed argument definitions.
        environment: environment variables that may be set.
        working_directory: fixed working directory (relative to scratch).
        input_files: file names read by the tool.
        output_files: file names the tool may write.
        stdin: whether the tool reads stdin.
        timeout: default timeout in seconds (``0`` = none).
        resource_limits: resource budget hints.
        network_policy: network access policy (``allowed``/``denied``/``scoped``).
        filesystem_policy: filesystem access policy.
        scope_policy: scope policy (``inherit`` by default; can never widen).
        safety_policy: safety policy reference.
        expected_exit_codes: acceptable process exit codes.
        expected_output_formats: formats the tool may produce.

    """

    command: str = ""
    arguments: tuple[ToolInputField, ...] = ()
    environment: tuple[str, ...] = ()
    working_directory: str = ""
    input_files: tuple[str, ...] = ()
    output_files: tuple[str, ...] = ()
    stdin: bool = False
    timeout: float = 0.0
    resource_limits: tuple[str, ...] = ()
    network_policy: str = "allowed"
    filesystem_policy: str = "scoped"
    scope_policy: str = "inherit"
    safety_policy: str = "inherit"
    expected_exit_codes: tuple[int, ...] = (0,)
    expected_output_formats: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolResourceRequirements:
    """Declared resource needs of a tool.

    Integrated with the existing ResourceManager and ParallelExecutionManager.

    Attributes:
        cpu_estimate: CPU estimate (percent or units).
        memory_estimate_mb: memory estimate in MB.
        network_estimate: network traffic estimate.
        disk_estimate_mb: scratch disk estimate in MB.
        timeout: default timeout in seconds.
        concurrency_class: concurrency class (``light``/``medium``/``heavy``).
        rate_limit: declared rate-limit profile.

    """

    cpu_estimate: float = 0.0
    memory_estimate_mb: float = 0.0
    network_estimate: str = "low"
    disk_estimate_mb: float = 0.0
    timeout: float = 0.0
    concurrency_class: str = "light"
    rate_limit: ToolRateLimitProfile | None = None


@dataclass(frozen=True, slots=True)
class ToolRateLimitProfile:
    """Declared rate limits for a tool.

    Effective rate limits are the MINIMUM of all applicable limits (tool,
    scope policy, mission policy, target policy and safety policy).

    Attributes:
        requests_per_second: sustained rate.
        concurrency: concurrent request cap.
        burst: burst allowance.
        cooldown_seconds: pause after a limit is hit.
        target_limits: per-target-key limits.

    """

    requests_per_second: float = 0.0
    concurrency: int = 0
    burst: int = 0
    cooldown_seconds: float = 0.0
    target_limits: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolSafetyProfile:
    """Safety posture of a tool.

    Attributes:
        safety_class: impact class (ceiling against authorization).
        destructive: the tool can destroy/alter state.
        requires_authorization: execution needs explicit authorization.
        approval_level: approval level name when required.
        allowed_for: mission types the tool may run under.

    """

    safety_class: ToolSafetyClass = ToolSafetyClass.PASSIVE
    destructive: bool = False
    requires_authorization: bool = False
    approval_level: str = ""
    allowed_for: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolScopeProfile:
    """How a tool interacts with the authorized scope.

    A tool adapter can never widen scope; redirects never auto-widen; AI
    parameters never widen scope.

    Attributes:
        follows_redirects: the tool follows HTTP redirects.
        redirect_scope: policy for redirect targets (``inherit``).
        expands_scope: the tool may discover assets (never authorized).
        network_boundary: network boundary policy.

    """

    follows_redirects: bool = False
    redirect_scope: str = "inherit"
    expands_scope: bool = False
    network_boundary: str = "inherit"


@dataclass(frozen=True, slots=True)
class ToolConfidenceCeiling:
    """Maximum confidence contribution a tool may provide.

    Prevents "scanner output = 99% confidence". The final confidence remains
    controlled by the existing confidence engine.

    Attributes:
        tool_id: the tool this ceiling belongs to.
        detection_ceiling: max confidence for detection evidence.
        behavioral_ceiling: max confidence for behavioral evidence.
        proof_ceiling: max confidence for proof evidence.

    """

    tool_id: str
    detection_ceiling: float = 0.5
    behavioral_ceiling: float = 0.8
    proof_ceiling: float = 0.95

    def ceiling_for(self, strength: EvidenceStrength) -> float:
        """Return the confidence ceiling for an evidence strength."""
        if strength is EvidenceStrength.PROOF:
            return self.proof_ceiling
        if strength is EvidenceStrength.BEHAVIORAL:
            return self.behavioral_ceiling
        return self.detection_ceiling


@dataclass(frozen=True, slots=True)
class ToolEvidenceMapping:
    """Deterministic mapping of a tool observation to canonical evidence.

    Tool output does NOT automatically equal evidence sufficient for a
    finding. The mapping defines what additional validation is required.

    Attributes:
        tool_id: the tool that produced the observation.
        observation_kind: canonical observation kind.
        evidence_type: canonical evidence type (see vulnerability_validation).
        strength: evidence strength class.
        vulnerability_classes: vulnerability classes the observation supports.
        proof_strategies: proof strategies the evidence can support.
        requires_validation: validation is mandatory before a finding.
        confidence_contribution: ceiling of the evidence contribution.

    """

    tool_id: str
    observation_kind: str
    evidence_type: str
    strength: EvidenceStrength = EvidenceStrength.DETECTION
    vulnerability_classes: tuple[str, ...] = ()
    proof_strategies: tuple[str, ...] = ()
    requires_validation: bool = True
    confidence_contribution: float = 0.0
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ToolProofCapability:
    """Proof capability a tool offers for a vulnerability class.

    Attributes:
        tool_id: the tool.
        vulnerability_class: vulnerability class (``sql-injection``...).
        proof_strategy_id: supported proof strategy id.
        supported_proof_types: proof types the tool can produce.
        required_inputs: inputs required to run a proof.
        produced_evidence: evidence the proof produces.
        limitations: known limitations of the tool's proof.
        safety_class: safety ceiling for proof execution.
        scope_requirements: scope requirements for proof execution.
        replay_support: the tool supports controlled replay.
        confidence_ceiling: max confidence the proof can support.

    """

    tool_id: str
    vulnerability_class: str
    proof_strategy_id: str = ""
    supported_proof_types: tuple[str, ...] = ()
    required_inputs: tuple[str, ...] = ()
    produced_evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    safety_class: ToolSafetyClass = ToolSafetyClass.ACTIVE
    scope_requirements: str = ""
    replay_support: bool = False
    confidence_ceiling: float = 0.9


@dataclass(frozen=True, slots=True)
class CanonicalObservation:
    """A normalized, canonical observation from a tool execution.

    Attributes:
        observation_id: unique observation identifier.
        target_id: the target the observation belongs to.
        asset_id: the asset (if any) the observation belongs to.
        tool_id: producing tool.
        tool_version: producing tool version.
        observation_kind: canonical kind.
        value: the raw observed value.
        normalized_value: the canonical normalized value.
        confidence: observation confidence in ``[0, 1]``.
        timestamp: UTC ISO-8601 timestamp.
        source: source label (tool/parser).
        raw_artifact_reference: reference to the preserved raw output.
        correlation_key: canonical identity for deduplication.
        provenance: provenance metadata.

    """

    observation_id: str
    target_id: str
    tool_id: str
    observation_kind: str
    value: str = ""
    normalized_value: str = ""
    asset_id: str = ""
    tool_version: str = ""
    confidence: float = 1.0
    timestamp: str = ""
    source: str = ""
    raw_artifact_reference: str = ""
    correlation_key: str = ""
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Structured result of a tool execution.

    The raw output is preserved as an artifact reference and never treated as
    a canonical finding.

    Attributes:
        execution_id: unique execution identifier.
        tool_id: executed tool.
        tool_version: executed tool version.
        mission_id: owning mission.
        target_id: assessed target.
        scope_id: scope the execution ran under.
        started_at: UTC ISO-8601 start.
        completed_at: UTC ISO-8601 completion.
        exit_status: exit code/status.
        raw_output_reference: reference to the preserved raw output.
        stdout_reference: reference to the captured stdout.
        stderr_reference: reference to the captured stderr.
        structured_output: parsed structured output.
        artifacts: artifact references.
        observations: canonical observations extracted.
        errors: error messages.
        resource_usage: resource usage snapshot.
        provenance: provenance metadata.

    """

    execution_id: str
    tool_id: str
    tool_version: str = ""
    mission_id: str = ""
    target_id: str = ""
    scope_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    exit_status: str = ""
    raw_output_reference: str = ""
    stdout_reference: str = ""
    stderr_reference: str = ""
    structured_output: dict[str, Any] = field(default_factory=dict)
    artifacts: tuple[str, ...] = ()
    observations: tuple[CanonicalObservation, ...] = ()
    errors: tuple[str, ...] = ()
    resource_usage: dict[str, float] = field(default_factory=dict)
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolSelection:
    """A full tool selection decision.

    Attributes:
        tool_id: selected tool.
        score: selection score in ``[0, 1]``.
        reasoning: why this tool was selected.
        alternatives: alternative tool ids.
        required_inputs: inputs the selected tool needs.
        expected_outputs: outputs the selected tool should produce.
        risk_level: assessed risk level.
        estimated_cost: estimated execution cost.
        expected_evidence: evidence types the tool is expected to provide.
        expected_proof_capability: the tool can support proof execution.
        confidence_ceiling: the tool's confidence contribution ceiling.

    """

    tool_id: str
    score: float = 0.0
    reasoning: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    required_inputs: tuple[str, ...] = ()
    expected_outputs: tuple[str, ...] = ()
    risk_level: str = "passive"
    estimated_cost: float = 0.0
    expected_evidence: tuple[str, ...] = ()
    expected_proof_capability: bool = False
    confidence_ceiling: float = 0.0


@dataclass(frozen=True, slots=True)
class ToolChainStep:
    """A single step in a tool chain.

    Attributes:
        step_id: stable step identifier.
        tool_id: tool to run.
        capability: capability the step provides.
        inputs: input values for the step.
        outputs: canonical output kinds produced.
        preconditions: preconditions that must hold.
        postconditions: postconditions the step establishes.
        on_success: condition to route on success.
        on_failure: condition to route on failure.
        on_inconclusive: condition to route on inconclusive results.
        timeout: step timeout in seconds.
        retry_policy: retry hints.
        safety_class: safety class of the step.

    """

    step_id: str
    tool_id: str
    capability: str = ""
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    postconditions: tuple[str, ...] = ()
    on_success: ToolChainCondition = ToolChainCondition.ON_SUCCESS
    on_failure: ToolChainCondition = ToolChainCondition.ON_FAILURE
    on_inconclusive: ToolChainCondition = ToolChainCondition.ON_SUCCESS
    timeout: float = 0.0
    retry_policy: str = ""
    safety_class: ToolSafetyClass = ToolSafetyClass.PASSIVE


@dataclass(frozen=True, slots=True)
class ToolChain:
    """A dependency-aware sequence of tool steps.

    Attributes:
        chain_id: unique chain identifier.
        mission_id: owning mission.
        objective: what the chain is trying to achieve.
        steps: ordered steps.
        dependencies: step_id → prerequisite step ids.
        conditions: routing conditions between steps.
        stop_conditions: conditions that stop the chain.
        abort_conditions: conditions that abort the chain.
        scope: scope the chain runs under.
        safety_policy: safety policy reference.
        created_by: creator label.
        version: chain version.

    """

    chain_id: str
    mission_id: str = ""
    objective: str = ""
    steps: tuple[ToolChainStep, ...] = ()
    dependencies: dict[str, tuple[str, ...]] = field(default_factory=dict)
    conditions: dict[str, str] = field(default_factory=dict)
    stop_conditions: tuple[str, ...] = ()
    abort_conditions: tuple[str, ...] = ()
    scope: str = ""
    safety_policy: str = ""
    created_by: str = "tool.intelligence"
    version: str = "1.0.0"

    def step(self, step_id: str) -> ToolChainStep | None:
        """Return the step with ``step_id`` or ``None``."""
        for item in self.steps:
            if item.step_id == step_id:
                return item
        return None


@dataclass(frozen=True, slots=True)
class ChainStepResult:
    """Outcome of one tool-chain step.

    Attributes:
        step_id: the step's identifier.
        tool_id: the tool that ran.
        status: the step's state.
        execution: execution result when available.
        observations: canonical observations produced.
        error: error message when failed.

    """

    step_id: str
    tool_id: str
    status: ChainStepState = ChainStepState.PENDING
    execution: ToolExecutionResult | None = None
    observations: tuple[CanonicalObservation, ...] = ()
    error: str = ""


@dataclass(frozen=True, slots=True)
class ToolChainResult:
    """Outcome of a tool-chain run.

    Attributes:
        chain_id: the chain's identifier.
        status: the chain's final state.
        step_results: results for each step.
        completed_steps: ids of completed steps.
        failed_steps: ids of failed steps.
        skipped_steps: ids of skipped steps.

    """

    chain_id: str
    status: ChainStatus = ChainStatus.PLANNED
    step_results: tuple[ChainStepResult, ...] = ()
    completed_steps: tuple[str, ...] = ()
    failed_steps: tuple[str, ...] = ()
    skipped_steps: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EscalationDecision:
    """A decision to escalate (or not) a tool execution.

    Every escalation requires a reason, evidence, scope, authorization,
    safety policy and tool capability.

    Attributes:
        tool_id: the tool to escalate to.
        level: the escalation level.
        allowed: whether the escalation is permitted.
        reason: justification.
        evidence: supporting evidence references.
        scope_ok: target stays inside scope.
        authorized: authorization permits the level.
        safety_class: safety class of the escalated tool.
        capability_ok: the tool provides the required capability.

    """

    tool_id: str
    level: EscalationLevel
    allowed: bool = False
    reason: str = ""
    evidence: tuple[str, ...] = ()
    scope_ok: bool = False
    authorized: bool = False
    safety_class: ToolSafetyClass = ToolSafetyClass.PASSIVE
    capability_ok: bool = False


@dataclass(frozen=True, slots=True)
class ConflictingToolEvidence:
    """Preserved disagreement between tools.

    Conflicting observations are never averaged — both are retained and a
    validation or proof-strategy selection is invoked.

    Attributes:
        correlation_key: the canonical identity in conflict.
        target: the target.
        vulnerability_class: the vulnerability class in question.
        observations: the conflicting observations (at least two).
        tools: the tools that disagree.
        detected_at: UTC ISO-8601 detection timestamp.

    """

    correlation_key: str
    target: str
    vulnerability_class: str = ""
    observations: tuple[CanonicalObservation, ...] = ()
    tools: tuple[str, ...] = ()
    detected_at: str = ""


@dataclass(frozen=True, slots=True)
class CorrelatedEvidenceChain:
    """A chain of correlated evidence across multiple tools.

    Attributes:
        chain_id: unique chain identifier.
        correlation_key: canonical identity.
        observations: the correlated observations.
        tools: the tools that contributed.
        vulnerability_classes: vulnerability classes implicated.
        strength: the strongest evidence strength observed.
        proof_candidate: the chain supports a proof candidate.
        confidence: aggregate confidence (ceiling-respected).

    """

    chain_id: str
    correlation_key: str
    observations: tuple[CanonicalObservation, ...] = ()
    tools: tuple[str, ...] = ()
    vulnerability_classes: tuple[str, ...] = ()
    strength: EvidenceStrength = EvidenceStrength.DETECTION
    proof_candidate: bool = False
    confidence: float = 0.0


@dataclass(frozen=True, slots=True)
class ToolExecutionRecord:
    """Target-specific tool execution history record.

    Written to the target intelligence database so HunterX knows "what have I
    already tested?" and "what should I NOT repeat?".

    Attributes:
        execution_id: unique execution identifier.
        tool_id: executed tool.
        tool_version: executed tool version.
        mission_id: owning mission.
        target: the assessed target.
        scope_id: scope the execution ran under.
        command_configuration: structured command configuration.
        observations: observation ids produced.
        evidence_ids: evidence ids produced.
        finding_ids: finding ids produced.
        proof_ids: proof ids produced.
        replay_ids: replay ids produced.
        status: execution status.
        started_at: UTC ISO-8601 start.
        completed_at: UTC ISO-8601 completion.
        duration_ms: execution duration.
        provenance: provenance metadata.

    """

    execution_id: str
    tool_id: str
    target: str
    tool_version: str = ""
    mission_id: str = ""
    scope_id: str = ""
    command_configuration: dict[str, Any] = field(default_factory=dict)
    observations: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    proof_ids: tuple[str, ...] = ()
    replay_ids: tuple[str, ...] = ()
    status: str = "completed"
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TargetIntelligenceSnapshot:
    """What HunterX currently knows about a target.

    Attributes:
        target: the target.
        known_assets: canonical asset identities.
        known_services: service identities.
        known_technologies: technology identities.
        known_endpoints: endpoint identities.
        known_parameters: parameter identities.
        known_vulnerabilities: vulnerability class ids.
        known_evidence: evidence references.
        known_proofs: proof references.
        known_exclusions: exclusions applied.
        first_seen: UTC ISO-8601 first observation.
        last_seen: UTC ISO-8601 latest observation.
        tool_coverage: tool_id → observation ids.
        test_coverage: capability/check → observation ids.
        confidence_state: per-category confidence.
        execution_history: tool execution records.

    """

    target: str
    known_assets: tuple[str, ...] = ()
    known_services: tuple[str, ...] = ()
    known_technologies: tuple[str, ...] = ()
    known_endpoints: tuple[str, ...] = ()
    known_parameters: tuple[str, ...] = ()
    known_vulnerabilities: tuple[str, ...] = ()
    known_evidence: tuple[str, ...] = ()
    known_proofs: tuple[str, ...] = ()
    known_exclusions: tuple[str, ...] = ()
    first_seen: str = ""
    last_seen: str = ""
    tool_coverage: dict[str, tuple[str, ...]] = field(default_factory=dict)
    test_coverage: dict[str, tuple[str, ...]] = field(default_factory=dict)
    confidence_state: dict[str, float] = field(default_factory=dict)
    execution_history: tuple[ToolExecutionRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class ToolReliabilityStats:
    """Historical reliability metrics per tool.

    Tools are never automatically disabled based solely on these metrics.

    Attributes:
        tool_id: the tool.
        successful_executions: total successes.
        failed_executions: total failures.
        parse_failures: total parse failures.
        false_positive_feedback: reported false-positive count.
        false_negative_feedback: reported false-negative count.
        evidence_quality: evidence quality score in ``[0, 1]``.
        proof_success_rate: fraction of proofs that succeeded.
        replay_success_rate: fraction of replays that succeeded.
        average_execution_time_ms: mean execution duration.
        samples: total recorded samples.

    """

    tool_id: str
    successful_executions: int = 0
    failed_executions: int = 0
    parse_failures: int = 0
    false_positive_feedback: int = 0
    false_negative_feedback: int = 0
    evidence_quality: float = 1.0
    proof_success_rate: float = 1.0
    replay_success_rate: float = 1.0
    average_execution_time_ms: float = 0.0
    samples: int = 0


@dataclass(frozen=True, slots=True)
class ToolAvailabilityReport:
    """Availability report for a tool capability.

    Attributes:
        tool_id: the tool.
        status: availability status.
        reason: explanation.
        checked_at: UTC ISO-8601 check timestamp.

    """

    tool_id: str
    status: ToolAvailabilityStatus = ToolAvailabilityStatus.INSTALLED
    reason: str = ""
    checked_at: str = ""

    @property
    def available(self) -> bool:
        """Return ``True`` only when the capability is installed."""
        return self.status is ToolAvailabilityStatus.INSTALLED


# ==========================================================================
# Sprint 031 — Full Toolchain Integration & Professional Tool Intelligence
#
# Canonical vocabulary for the complete authorized offensive-security
# toolchain. HunterX understands WHAT a tool does, WHEN/WHY to use it, WHAT
# it requires, HOW to invoke it safely, WHAT its output means and — just as
# importantly — WHAT its output does NOT prove.
# ==========================================================================


class ToolOutputSemantics(Enum):
    """Canonical semantic state of a tool result.

    Tool failure must never be interpreted as vulnerability absence. A
    scanner that crashed, timed out or was rate-limited reports
    ``ERROR``/``TIMEOUT``/``RATE_LIMITED`` — never ``NOT_FOUND``.
    """

    FOUND = "found"
    NOT_FOUND = "not-found"
    UNKNOWN = "unknown"
    ERROR = "error"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate-limited"
    UNSUPPORTED = "unsupported"
    INVALID_INPUT = "invalid-input"

    @property
    def definitive(self) -> bool:
        """Return ``True`` when the semantics can support a NOT_FOUND claim."""
        return self is ToolOutputSemantics.FOUND or self is ToolOutputSemantics.NOT_FOUND


class EvidenceClass(Enum):
    """Classification of evidence extracted from tool output.

    Tool output alone must never automatically become a confirmed finding.
    ``CANDIDATE`` evidence requires validation before it can be promoted.
    """

    DIRECT = "direct"
    SUPPORTING = "supporting"
    CANDIDATE = "candidate"
    NEGATIVE = "negative"
    EXECUTION = "execution"
    VALIDATION = "validation"
    METADATA = "metadata"


@dataclass(frozen=True, slots=True)
class ToolEvidence:
    """Evidence extracted from a tool result.

    Attributes:
        evidence_id: unique evidence identifier.
        tool_id: producing tool.
        execution_id: owning execution.
        target: the assessed target.
        evidence_class: canonical evidence class.
        evidence_type: canonical evidence type (see vulnerability_validation).
        content: sanitized evidence content (secrets redacted).
        artifact_reference: reference to the preserved raw output.
        extracted_at: UTC ISO-8601 extraction timestamp.
        confidence: evidence confidence in ``[0, 1]``.
        validated: whether validation has promoted this evidence.
        provenance: provenance metadata.

    """

    evidence_id: str
    tool_id: str
    evidence_class: EvidenceClass = EvidenceClass.CANDIDATE
    evidence_type: str = ""
    target: str = ""
    execution_id: str = ""
    content: str = ""
    artifact_reference: str = ""
    extracted_at: str = ""
    confidence: float = 0.0
    validated: bool = False
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolParser:
    """Versioned contract of a tool output parser.

    Attributes:
        parser_id: stable parser identifier.
        tool: tool whose output the parser understands.
        tool_versions: compatible tool versions (empty = all).
        input_format: input format (``json``, ``jsonl``, ``xml``, ``csv``, ``text``...).
        schema: schema/record shape the parser produces.
        parser_version: semantic version of the parser itself.
        output_mappings: record field → canonical field mappings.
        error_handling: how malformed/partial input is handled.
        backward_compatible: the parser tolerates older tool output.

    """

    parser_id: str
    tool: str = ""
    tool_versions: tuple[str, ...] = ()
    input_format: str = "text"
    schema: str = ""
    parser_version: str = "1.0.0"
    output_mappings: dict[str, str] = field(default_factory=dict)
    error_handling: str = "skip-malformed"
    backward_compatible: bool = True


@dataclass(frozen=True, slots=True)
class ToolNormalizer:
    """Versioned contract of a tool output normalizer.

    Attributes:
        normalizer_id: stable normalizer identifier.
        tool: tool whose records the normalizer canonicalizes.
        schema: canonical observation schema the normalizer produces.
        normalizer_version: semantic version of the normalizer itself.
        observation_mappings: record field → canonical observation kind.
        migration: migration behavior between normalizer versions.
        backward_compatible: the normalizer tolerates older record shapes.

    """

    normalizer_id: str
    tool: str = ""
    schema: str = "canonical-observation"
    normalizer_version: str = "1.0.0"
    observation_mappings: dict[str, str] = field(default_factory=dict)
    migration: str = "none"
    backward_compatible: bool = True


@dataclass(frozen=True, slots=True)
class ToolStrategy:
    """Selection strategy for a capability across the toolchain.

    Attributes:
        capability: capability the strategy serves.
        primary: primary tool id.
        fallbacks: ordered fallback tool ids.
        complementary: complementary tool ids (merge/cross-validate).
        specialized: specialized tool ids for narrow contexts.
        merge_policy: how outputs from multiple tools are combined
            (``deduplicate``, ``correlate``, ``cross-validate``, ``keep-separate``).
        rationale: why this strategy exists.

    """

    capability: str
    primary: str = ""
    fallbacks: tuple[str, ...] = ()
    complementary: tuple[str, ...] = ()
    specialized: tuple[str, ...] = ()
    merge_policy: str = "deduplicate"
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class ToolExecutionProfile:
    """Full structured execution profile of a tool run.

    Attributes:
        execution_id: unique execution identifier.
        tool: executed tool.
        tool_version: executed tool version.
        mission_id: owning mission.
        campaign_id: owning campaign.
        target_id: assessed target.
        scope: scope the execution ran under.
        arguments: structured argument/configuration reference.
        start_time: UTC ISO-8601 start.
        end_time: UTC ISO-8601 completion.
        status: lifecycle status (``running``/``completed``/``failed``/...).
        exit_code: process exit code (``None`` when not a process).
        stdout_reference: reference to captured stdout.
        stderr_reference: reference to captured stderr.
        structured_output_reference: reference to structured output.
        resource_usage: resource usage snapshot.
        network_activity: network activity metadata where available.

    """

    execution_id: str
    tool: str
    tool_version: str = ""
    mission_id: str = ""
    campaign_id: str = ""
    target_id: str = ""
    scope: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    start_time: str = ""
    end_time: str = ""
    status: str = "planned"
    exit_code: int | None = None
    stdout_reference: str = ""
    stderr_reference: str = ""
    structured_output_reference: str = ""
    resource_usage: dict[str, float] = field(default_factory=dict)
    network_activity: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Unified result of a tool execution with canonical semantics.

    Attributes:
        execution_id: unique execution identifier.
        tool_id: executed tool.
        semantics: canonical output semantics.
        exit_code: process exit code (``None`` when not a process).
        observations: canonical observations extracted.
        evidence: canonical evidence extracted.
        parsed_records: parsed structured records.
        normalized: whether normalization completed.
        errors: error messages.
        duration_ms: execution duration in milliseconds.
        raw_artifact_reference: reference to the preserved raw output.

    """

    execution_id: str
    tool_id: str
    semantics: ToolOutputSemantics = ToolOutputSemantics.UNKNOWN
    exit_code: int | None = None
    observations: tuple[CanonicalObservation, ...] = ()
    evidence: tuple[ToolEvidence, ...] = ()
    parsed_records: tuple[dict[str, Any], ...] = ()
    normalized: bool = False
    errors: tuple[str, ...] = ()
    duration_ms: int = 0
    raw_artifact_reference: str = ""


@dataclass(frozen=True, slots=True)
class ToolEvidenceConfidence:
    """Confidence assessment of a tool's evidence contribution.

    Combines tool reliability, result completeness, output quality, version,
    validation state, corroboration and false-positive characteristics into an
    overall confidence score. Never equal to finding confidence.

    Attributes:
        tool_id: the tool.
        reliability: historical reliability in ``[0, 1]``.
        completeness: result completeness in ``[0, 1]``.
        output_quality: output quality in ``[0, 1]``.
        version_freshness: version compatibility in ``[0, 1]``.
        validation_state: validation state in ``[0, 1]`` (0 = unvalidated).
        corroboration: corroboration by other tools in ``[0, 1]``.
        false_positive_characteristics: known FP tendency in ``[0, 1]``
            (higher = more FP-prone).
        historical_reliability: long-run reliability in ``[0, 1]``.
        overall: computed overall confidence in ``[0, 1]``.

    """

    tool_id: str
    reliability: float = 0.0
    completeness: float = 0.0
    output_quality: float = 0.0
    version_freshness: float = 0.0
    validation_state: float = 0.0
    corroboration: float = 0.0
    false_positive_characteristics: float = 0.0
    historical_reliability: float = 0.0
    overall: float = 0.0

    def compute(self) -> ToolEvidenceConfidence:
        """Return a new confidence with ``overall`` recomputed."""
        overall = (
            self.reliability * 0.25
            + self.completeness * 0.15
            + self.output_quality * 0.15
            + self.version_freshness * 0.05
            + self.validation_state * 0.15
            + self.corroboration * 0.15
            - self.false_positive_characteristics * 0.1
        )
        overall = max(0.0, min(1.0, overall))
        return ToolEvidenceConfidence(
            tool_id=self.tool_id,
            reliability=self.reliability,
            completeness=self.completeness,
            output_quality=self.output_quality,
            version_freshness=self.version_freshness,
            validation_state=self.validation_state,
            corroboration=self.corroboration,
            false_positive_characteristics=self.false_positive_characteristics,
            historical_reliability=self.historical_reliability,
            overall=overall,
        )
