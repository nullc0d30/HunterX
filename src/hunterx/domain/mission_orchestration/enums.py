# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration — canonical value vocabulary.

Sprint 032. Enums consumed by the autonomous mission orchestration engine: the
typed mission event vocabulary, hypothesis states, finding stages, behavior
classifications, orchestration strategies, stop conditions, negative-evidence
kinds and confidence components. These enums are the machine vocabulary of the
machine-readable contract ``capabilities/autonomous-mission-orchestration.json``.

The orchestration layer deliberately reuses the Sprint 027 planning vocabulary
(``MissionObjective``, ``MissionMode``, ``MissionState``,
``AdaptiveMission``) — those enums are NOT duplicated here. This module only
adds concepts that live above the planner: observation-driven hypothesis
states, evidence-first finding stages, baseline/differential testing,
negative evidence, orchestration strategies and stop conditions.
"""

from __future__ import annotations

from enum import StrEnum


class HypothesisState(StrEnum):
    """Evidence-driven state of a mission hypothesis.

    A hypothesis is never a conclusion: it transitions only when observations
    move it. ``NOVEL_BEHAVIOR`` marks behavior that matches no known signature
    and must be characterized before it can be validated or disproved.
    """

    PROPOSED = "proposed"
    SUPPORTED = "supported"
    WEAKLY_SUPPORTED = "weakly_supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    VALIDATED = "validated"
    DISPROVED = "disproved"
    NOVEL_BEHAVIOR = "novel_behavior"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` for states that end a hypothesis lifecycle."""
        return self in (
            HypothesisState.VALIDATED,
            HypothesisState.DISPROVED,
            HypothesisState.REFUTED,
        )


class FindingStage(StrEnum):
    """Evidence-first progression of an orchestrated finding.

    A scanner result is a ``CANDIDATE`` only — it never becomes reportable
    without independent validation, proof and impact assessment.
    """

    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    VERIFIED = "verified"
    PROVEN = "proven"
    REPORT_READY = "report_ready"


class BehaviorClass(StrEnum):
    """Classification of an observed behavior.

    Novel behavior never requires a CVE or existing signature: it is either a
    known pattern, a variant of one, a misconfiguration, an
    application-specific behavior, or a novel candidate that must be validated
    through the experiment loop.
    """

    KNOWN = "known"
    VARIANT = "variant"
    MISCONFIGURATION = "misconfiguration"
    APPLICATION_SPECIFIC = "application_specific"
    NOVEL_CANDIDATE = "novel_candidate"
    NOVEL_VALIDATED = "novel_validated"


class StrategyKind(StrEnum):
    """Orchestration strategy for selecting the next action.

    The default is always :data:`StrategyKind.ADAPTIVE`: breadth-first,
    depth-first, risk-first, asset-first, technology-first, vulnerability-first,
    evidence-first, coverage-first and hypothesis-first are available as
    explicit strategies that modify the decision weights.
    """

    BREADTH_FIRST = "breadth_first"
    DEPTH_FIRST = "depth_first"
    RISK_FIRST = "risk_first"
    ASSET_FIRST = "asset_first"
    TECHNOLOGY_FIRST = "technology_first"
    VULNERABILITY_FIRST = "vulnerability_first"
    EVIDENCE_FIRST = "evidence_first"
    COVERAGE_FIRST = "coverage_first"
    HYPOTHESIS_FIRST = "hypothesis_first"
    ADAPTIVE = "adaptive"


class StopCondition(StrEnum):
    """Reasons a mission may reach a final state.

    Stop conditions are evaluated deterministically after every observation;
    none of them allow the orchestrator to exceed the mission's policy budget.
    ``BLOCKED`` is the honest terminal used when no actionable work remains
    (or no tool is available) while the objectives are not complete — it is
    never reported as success.
    """

    OBJECTIVES_COMPLETE = "objectives_complete"
    COVERAGE_TARGET_ACHIEVED = "coverage_target_achieved"
    HIGH_VALUE_HYPOTHESES_RESOLVED = "high_value_hypotheses_resolved"
    FINDINGS_VALIDATED = "findings_validated"
    ATTACK_SURFACE_EXHAUSTED = "attack_surface_exhausted"
    RESOURCE_BUDGET_EXHAUSTED = "resource_budget_exhausted"
    TIME_BUDGET_EXHAUSTED = "time_budget_exhausted"
    OPERATOR_CANCELLED = "operator_cancelled"
    UNRECOVERABLE_FAILURE = "unrecoverable_failure"
    BLOCKED = "blocked"


class NegativeEvidenceKind(StrEnum):
    """Bounded negative-evidence categories.

    "Not found" is never "not vulnerable": each negative record keeps the exact
    tool, version, input, conditions and outcome that produced it.
    """

    TESTED = "tested"
    NOT_VULNERABLE = "not_vulnerable"
    NOT_REPRODUCIBLE = "not_reproducible"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


class MissionEventType(StrEnum):
    """Typed events emitted and consumed by the orchestrator."""

    MISSION_STARTED = "mission.started"
    MISSION_PHASE_STARTED = "mission.phase.started"
    MISSION_PHASE_COMPLETED = "mission.phase.completed"
    MISSION_ACTION_SELECTED = "mission.action.selected"
    MISSION_ACTION_STARTED = "mission.action.started"
    MISSION_ACTION_COMPLETED = "mission.action.completed"
    MISSION_OBSERVATION_CREATED = "mission.observation.created"
    MISSION_HYPOTHESIS_CREATED = "mission.hypothesis.created"
    MISSION_HYPOTHESIS_UPDATED = "mission.hypothesis.updated"
    MISSION_FINDING_CREATED = "mission.finding.created"
    MISSION_FINDING_VALIDATED = "mission.finding.validated"
    MISSION_PROOF_STARTED = "mission.proof.started"
    MISSION_PROOF_COMPLETED = "mission.proof.completed"
    MISSION_ATTACK_PATH_CREATED = "mission.attack_path.created"
    MISSION_BRANCH_CREATED = "mission.branch.created"
    MISSION_CHECKPOINT_CREATED = "mission.checkpoint.created"
    MISSION_REASSESSMENT_STARTED = "mission.reassessment.started"
    MISSION_COMPLETED = "mission.completed"


class ConfidenceComponent(StrEnum):
    """Components that compose an evidence-driven confidence score.

    Confidence is a weighted aggregate over deterministic evidence components —
    never an opaque AI probability.
    """

    DETECTION_EVIDENCE = "detection_evidence"
    BEHAVIORAL_EVIDENCE = "behavioral_evidence"
    INDEPENDENT_VERIFICATION = "independent_verification"
    IMPACT_EVIDENCE = "impact_evidence"
    REPRODUCIBILITY = "reproducibility"
    TOOL_RELIABILITY = "tool_reliability"
    EVIDENCE_QUALITY = "evidence_quality"
    CORROBORATION = "corroboration"
    HISTORICAL_TARGET_BEHAVIOR = "historical_target_behavior"


class DifferentialSignal(StrEnum):
    """Behavior deltas a differential test can detect."""

    STATUS_CHANGE = "status_change"
    LENGTH_CHANGE = "length_change"
    HEADER_CHANGE = "header_change"
    REFLECTION = "reflection"
    TIMING_DELTA = "timing_delta"
    CALLBACK = "callback"
    ERROR_BEHAVIOR = "error_behavior"
    CONTENT_MUTATION = "content_mutation"
    NO_DELTA = "no_delta"


class NovelPipelineStage(StrEnum):
    """Stages of the novel-vulnerability discovery pipeline."""

    UNKNOWN_BEHAVIOR = "unknown_behavior"
    BEHAVIORAL_MODEL = "behavioral_model"
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    OBSERVATION = "observation"
    NEW_HYPOTHESIS = "new_hypothesis"
    MINIMAL_PROOF = "minimal_proof"
    VALIDATED_BEHAVIOR = "validated_behavior"


class MissionRunStatus(StrEnum):
    """Lifecycle of a single mission execution run."""

    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    RESUMED = "resumed"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ReasoningTraceKind(StrEnum):
    """Kinds of structured reasoning-trace entries.

    The trace is an auditable reasoning graph (observation → hypothesis →
    decision → evidence → action → result), never arbitrary chain-of-thought.
    """

    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    EVIDENCE = "evidence"
    ACTION = "action"
    RESULT = "result"
    RATIONALE = "rationale"


class MissionPhase(StrEnum):
    """Canonical orchestration phases.

    These mirror the Sprint 027 ``MissionState`` progression at orchestration
    granularity; the orchestrator advances them as the mission adapts.
    """

    TARGET_MODELING = "target_modeling"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    ATTACK_SURFACE_MAPPING = "attack_surface_mapping"
    TECHNOLOGY_ANALYSIS = "technology_analysis"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    HYPOTHESIS_ANALYSIS = "hypothesis_analysis"
    VALIDATION = "validation"
    PROOF = "proof"
    IMPACT_ANALYSIS = "impact_analysis"
    CORRELATION = "correlation"
    REASSESSMENT = "reassessment"
    REPORTING = "reporting"


__all__ = [
    "BehaviorClass",
    "ConfidenceComponent",
    "DifferentialSignal",
    "FindingStage",
    "HypothesisState",
    "MissionEventType",
    "MissionPhase",
    "MissionRunStatus",
    "NegativeEvidenceKind",
    "NovelPipelineStage",
    "ReasoningTraceKind",
    "StopCondition",
    "StrategyKind",
]
