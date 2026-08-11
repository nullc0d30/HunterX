# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal Security Tool Mastery — domain models.

The mastery layer is the Sprint 025 contract that turns HunterX from "an
orchestrator that can execute security tools" into "a professional security
operator that deeply understands and correctly uses every integrated tool".

Pure data models. No I/O, no execution. These are the structured contracts
that every mastery subsystem (arsenal registry, relationship graph, playbook
engine, mission selector, tool history, coverage engine, dataset registry,
parser regression, result replay) reads and writes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunterx.domain.tool_intelligence import (
    ToolCompatibility,
    ToolConfidenceCeiling,
    ToolEvidenceMapping,
    ToolKnowledge,
    ToolMetadata,
    ToolProofCapability,
)


class ToolSupportLevel(Enum):
    """How completely HunterX supports an integrated tool.

    A tool is ``FULLY_SUPPORTED`` only when execution, parsing, normalization,
    capability knowledge, evidence mapping, error handling, version handling,
    scope, safety and tests are all implemented. Merely being able to launch
    the binary never confers full support.
    """

    FULLY_SUPPORTED = "fully-supported"
    EXECUTION_ONLY = "execution-only"
    PARTIAL_SUPPORT = "partial-support"
    PARSER_ONLY = "parser-only"
    KNOWLEDGE_ONLY = "knowledge-only"
    UNAVAILABLE = "unavailable"


class ToolRelationshipKind(Enum):
    """Kinds of relationships in the :class:`ToolRelationshipGraph`."""

    REQUIRES = "requires"
    ENABLES = "enables"
    COMPLEMENTS = "complements"
    VALIDATES = "validates"
    CORROBORATES = "corroborates"
    REPLACES = "replaces"
    CONFLICTS_WITH = "conflicts-with"
    SPECIALIZES = "specializes"
    PRECEDES = "precedes"
    FOLLOWS = "follows"
    ESCALATES_TO = "escalates-to"
    DEESCALATES_TO = "deescalates-to"


class ToolPlaybookCategory(Enum):
    """High-level categories a data-driven playbook belongs to."""

    RECON = "recon"
    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    VALIDATION = "validation"
    PROOF = "proof"
    ASSESSMENT = "assessment"


class ToolHistoryStatus(Enum):
    """Outcome of a recorded tool run against a target."""

    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class ToolMasterProfile:
    """The complete, authoritative profile of one integrated security tool.

    Aggregates every dimension HunterX must understand about a tool: identity,
    capabilities, version model, command tree, options, input/output contracts,
    parser/normalizer wiring, evidence and proof semantics, safety/scope/
    resource models, failure behavior, chaining, operational knowledge and
    support classification.

    Attributes:
        tool_id: unique identifier matching ``ToolMetadata.tool_id``.
        metadata: upstream project metadata.
        knowledge: capability/input/output/invocation knowledge.
        compatibility: platform/runtime compatibility.
        support_level: how completely HunterX supports the tool.
        capability_ids: canonical capabilities the tool provides.
        supported_targets: target types the tool accepts.
        supported_protocols: protocols the tool speaks.
        command_tree: conceptual command tree (``mode -> operation -> ...``).
        global_options: option names that apply to every invocation.
        input_formats: formats the tool consumes.
        output_formats: formats the tool emits.
        structured_output_formats: structured formats (JSON/XML/JSONL...).
        exit_codes: meaningful exit codes and their meaning.
        error_indicators: output patterns signalling errors.
        warning_indicators: output patterns signalling warnings.
        partial_result_indicators: output patterns signalling partial results.
        false_positive_risks: known false-positive behaviors.
        false_negative_risks: known false-negative limitations.
        version_constraints: accepted version ranges.
        known_version_issues: version-specific behavioral notes.
        parser_id: registered parser identifier.
        normalizer_id: registered normalizer identifier.
        adapter_id: SDK adapter identifier (``package.module:Class``).
        evidence_mapping: canonical evidence mapping for the tool.
        proof_capabilities: proof capabilities the tool offers.
        confidence_ceiling: confidence ceiling applied to tool output.
        recommended_predecessors: tool_ids that should run before this one.
        recommended_successors: tool_ids that should run after this one.
        alternative_tools: tool_ids with overlapping capability.
        complementary_tools: tool_ids that pair well with this one.
        safety_class: canonical safety class label (passive/read-only/...).
        destructive: whether the tool can change target state.
        scope_requirements: scope constraints.
        resource_requirements: resource model summary.
        rate_limits: known/expected rate limits.
        mission_priority: mission type -> priority mapping.
        operational_knowledge: free-form operator knowledge.
        provenance: where the profile came from.
        profile_version: schema version of this profile.

    """

    tool_id: str
    metadata: ToolMetadata
    knowledge: ToolKnowledge
    support_level: ToolSupportLevel = ToolSupportLevel.KNOWLEDGE_ONLY
    compatibility: ToolCompatibility | None = None
    capability_ids: tuple[str, ...] = ()
    supported_targets: tuple[str, ...] = ()
    supported_protocols: tuple[str, ...] = ()
    command_tree: tuple[str, ...] = ()
    global_options: tuple[str, ...] = ()
    input_formats: tuple[str, ...] = ()
    output_formats: tuple[str, ...] = ()
    structured_output_formats: tuple[str, ...] = ()
    exit_codes: tuple[str, ...] = ()
    error_indicators: tuple[str, ...] = ()
    warning_indicators: tuple[str, ...] = ()
    partial_result_indicators: tuple[str, ...] = ()
    false_positive_risks: tuple[str, ...] = ()
    false_negative_risks: tuple[str, ...] = ()
    version_constraints: tuple[str, ...] = ()
    known_version_issues: tuple[str, ...] = ()
    parser_id: str = ""
    normalizer_id: str = ""
    adapter_id: str = ""
    evidence_mapping: ToolEvidenceMapping | None = None
    proof_capabilities: tuple[ToolProofCapability, ...] = ()
    confidence_ceiling: ToolConfidenceCeiling | None = None
    recommended_predecessors: tuple[str, ...] = ()
    recommended_successors: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()
    complementary_tools: tuple[str, ...] = ()
    safety_class: str = "passive"
    destructive: bool = False
    scope_requirements: str = ""
    resource_requirements: str = ""
    rate_limits: str = ""
    mission_priority: dict[str, int] = field(default_factory=dict)
    operational_knowledge: tuple[str, ...] = ()
    provenance: dict[str, str] = field(default_factory=dict)
    profile_version: str = "1.0.0"

    def __str__(self) -> str:
        return f"ToolMasterProfile({self.tool_id}, {self.support_level.value})"


@dataclass(frozen=True, slots=True)
class ToolRelationship:
    """A single directed edge in the tool relationship graph.

    Attributes:
        source: tool_id of the source tool.
        target: tool_id of the target tool.
        kind: relationship kind.
        capability: optional capability the edge is about.
        rationale: human-readable rationale.
        strength: optional evidence of how strong the relationship is.

    """

    source: str
    target: str
    kind: ToolRelationshipKind
    capability: str = ""
    rationale: str = ""
    strength: float = 0.5


@dataclass(frozen=True, slots=True)
class ToolPlaybookStep:
    """One step of a data-driven tool playbook.

    A playbook step declares an objective and the capabilities required to
    achieve it. It does NOT hardcode unrestricted attack commands; concrete
    tool selection is deferred to the mission-aware selector at runtime.
    """

    step_id: str
    objective: str
    required_capabilities: tuple[str, ...] = ()
    preferred_tools: tuple[str, ...] = ()
    fallback_tools: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    evidence_requirements: tuple[str, ...] = ()
    proof_requirements: tuple[str, ...] = ()
    safety_class: str = "passive"


@dataclass(frozen=True, slots=True)
class ToolPlaybook:
    """A data-driven, ordered tool playbook for a class of work.

    Attributes:
        playbook_id: unique identifier.
        name: human-readable name.
        category: playbook category.
        objective: what the playbook accomplishes.
        mission_types: mission types this playbook is appropriate for.
        steps: ordered steps.
        version: playbook version.
        stop_conditions: overall stop conditions.
        description: free-form description.

    """

    playbook_id: str
    name: str
    category: ToolPlaybookCategory
    objective: str
    mission_types: tuple[str, ...] = ()
    steps: tuple[ToolPlaybookStep, ...] = ()
    stop_conditions: tuple[str, ...] = ()
    version: str = "1.0.0"
    description: str = ""


@dataclass(frozen=True, slots=True)
class ToolDataset:
    """Provenance and metadata for a dataset integrated into HunterX.

    Datasets (SecLists, FuzzDB, PayloadsAllTheThings, Nuclei templates, ...)
    are knowledge, not executable truth. Each is versioned and traced.
    """

    dataset_id: str
    name: str
    version: str = ""
    source: str = ""
    license: str = ""
    category: str = ""
    purpose: str = ""
    encoding: str = "utf-8"
    size_bytes: int = 0
    checksum: str = ""
    update_timestamp: str = ""
    compatibility: tuple[str, ...] = ()
    safety_classification: str = "safe"
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UnifiedToolResult:
    """The unified, canonical result envelope for a tool execution.

    A clean tool result does NOT automatically become ``NOT_VULNERABLE``. The
    envelope preserves raw artifacts, structured output, observations,
    candidate findings, validation results, proof candidates, warnings and
    errors, plus provenance and coverage deltas.
    """

    execution_id: str
    tool_id: str
    tool_version: str = ""
    target: str = ""
    scope_id: str = ""
    mission_id: str = ""
    status: str = "completed"
    raw_artifact_reference: str = ""
    structured_output: dict[str, Any] = field(default_factory=dict)
    observations: tuple[Any, ...] = ()
    candidate_findings: tuple[Any, ...] = ()
    validation_results: tuple[Any, ...] = ()
    proof_candidates: tuple[Any, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    classification: tuple[str, ...] = ()
    provenance: dict[str, str] = field(default_factory=dict)
    coverage_delta: dict[str, Any] = field(default_factory=dict)
    intelligence_delta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolHistoryEntry:
    """A recorded tool run against a target/asset/mission.

    Attributes:
        entry_id: unique identifier.
        tool_id: executed tool.
        target: the target the tool ran against.
        asset_id: optional asset the run was scoped to.
        mission_id: optional mission the run belonged to.
        tool_version: executed version.
        configuration: configuration snapshot.
        status: outcome status.
        started_at: UTC start timestamp.
        completed_at: UTC completion timestamp.
        observations_count: count of observations produced.
        evidence_ids: evidence identifiers produced.
        learned: what the run taught HunterX.
        unknown: what remains unknown.
        provenance: provenance metadata.

    """

    entry_id: str
    tool_id: str
    target: str
    asset_id: str = ""
    mission_id: str = ""
    tool_version: str = ""
    configuration: dict[str, Any] = field(default_factory=dict)
    status: ToolHistoryStatus = ToolHistoryStatus.COMPLETED
    started_at: str = ""
    completed_at: str = ""
    observations_count: int = 0
    evidence_ids: tuple[str, ...] = ()
    learned: str = ""
    unknown: str = ""
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolCoverageReport:
    """Coverage analysis of the arsenal.

    Attributes:
        total_tools: tools represented in the arsenal.
        by_support_level: support level -> tool count.
        capability_coverage: capability id -> tool ids.
        capability_gaps: capabilities with no provider.
        tools_by_capability: tool id -> capability ids.
        report_timestamp: UTC timestamp of the report.

    """

    total_tools: int = 0
    by_support_level: dict[str, int] = field(default_factory=dict)
    capability_coverage: dict[str, tuple[str, ...]] = field(default_factory=dict)
    capability_gaps: tuple[str, ...] = ()
    tools_by_capability: dict[str, tuple[str, ...]] = field(default_factory=dict)
    report_timestamp: str = ""


@dataclass(frozen=True, slots=True)
class ToolSelectionDecision:
    """An explainable, mission-aware tool selection.

    Attributes:
        tool_id: selected tool.
        reason: why it was selected.
        required_capability: capability the selection satisfies.
        expected_information_gain: what HunterX expects to learn.
        expected_evidence: evidence classes the tool can produce.
        expected_proof_capability: whether the tool supports proof.
        risk: safety class label.
        cost: estimated cost score.
        alternatives: alternative tools considered.
        why_alternatives_rejected: reasons alternatives were rejected.
        score: TIP selection score.

    """

    tool_id: str = ""
    reason: str = ""
    required_capability: str = ""
    expected_information_gain: tuple[str, ...] = ()
    expected_evidence: tuple[str, ...] = ()
    expected_proof_capability: bool = False
    risk: str = "passive"
    cost: float = 0.0
    alternatives: tuple[str, ...] = ()
    why_alternatives_rejected: tuple[str, ...] = ()
    score: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-compatible dictionary."""
        return {
            "tool_id": self.tool_id,
            "reason": self.reason,
            "required_capability": self.required_capability,
            "expected_information_gain": list(self.expected_information_gain),
            "expected_evidence": list(self.expected_evidence),
            "expected_proof_capability": self.expected_proof_capability,
            "risk": self.risk,
            "cost": self.cost,
            "alternatives": list(self.alternatives),
            "why_alternatives_rejected": list(self.why_alternatives_rejected),
            "score": self.score,
        }
