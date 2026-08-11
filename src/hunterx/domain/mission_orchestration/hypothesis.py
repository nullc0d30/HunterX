# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Hypothesis loop engine.

Sprint 032. The central loop of the autonomous mission:

    OBSERVE → HYPOTHESIZE → TEST → OBSERVE → UPDATE HYPOTHESIS → TEST →
    VERIFY → PROVE

A hypothesis transitions through evidence-driven states (SUPPORTED /
WEAKLY_SUPPORTED / REFUTED / INCONCLUSIVE / VALIDATED / DISPROVED /
NOVEL_BEHAVIOR) and the novel-vulnerability pipeline
(UNKNOWN_BEHAVIOR → BEHAVIORAL_MODEL → HYPOTHESIS → EXPERIMENT → OBSERVATION →
NEW_HYPOTHESIS → MINIMAL_PROOF → VALIDATED_BEHAVIOR) so HunterX does not depend
exclusively on known signatures.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.domain.mission_orchestration.enums import (
    BehaviorClass,
    HypothesisState,
    NovelPipelineStage,
)
from hunterx.domain.mission_orchestration.models import (
    MissionHypothesis,
    MissionObservation,
    NovelBehaviorRecord,
)
from hunterx.domain.target_intelligence.enums import HypothesisType
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class HypothesisLoopEngine:
    """Advance the observation → hypothesis → validation → proof loop.

    The engine is pure state: it derives hypothesis transitions and novel
    pipeline stages from observations. It never executes tools.
    """

    #: Number of supporting evidence refs needed to call a hypothesis supported.
    SUPPORT_THRESHOLD = 2

    def update(
        self,
        hypothesis: MissionHypothesis,
        *,
        supporting: tuple[str, ...] = (),
        contradicting: tuple[str, ...] = (),
        tested_action: str = "",
        observation: MissionObservation | None = None,
    ) -> MissionHypothesis:
        """Recompute the hypothesis state from new evidence.

        Rules (deterministic):
        * any contradicting evidence with no supporting evidence → REFUTED.
        * contradicting evidence that outweighs supporting → DISPROVED.
        * ≥ ``SUPPORT_THRESHOLD`` supporting evidence, none contradicting →
          SUPPORTED (independent verification is required before VALIDATED).
        * supporting evidence but below threshold → SUPPORTED /
          WEAKLY_SUPPORTED by strength.
        * neither side moves the hypothesis → INCONCLUSIVE.
        """
        supporting_refs = tuple(dict.fromkeys(hypothesis.supporting_evidence + tuple(supporting)))
        contradicting_refs = tuple(dict.fromkeys(hypothesis.contradicting_evidence + tuple(contradicting)))
        tested = tested_action or observation.action_id if observation else tested_action
        tested_actions = tuple(dict.fromkeys(hypothesis.tested_actions + ((tested,) if tested else ())))

        state = hypothesis.state
        behavior_class = hypothesis.behavior_class

        if contradicting_refs and not supporting_refs:
            state = HypothesisState.REFUTED
        elif len(contradicting_refs) > len(supporting_refs) and supporting_refs:
            state = HypothesisState.DISPROVED
        elif len(supporting_refs) >= self.SUPPORT_THRESHOLD and not contradicting_refs:
            state = HypothesisState.SUPPORTED
            behavior_class = _classify_validated(behavior_class)
        elif supporting_refs:
            state = (
                HypothesisState.SUPPORTED
                if len(supporting_refs) >= 2
                else HypothesisState.WEAKLY_SUPPORTED
            )
        elif state is HypothesisState.PROPOSED and not supporting_refs and not contradicting_refs:
            state = HypothesisState.INCONCLUSIVE

        return replace(
            hypothesis,
            state=state,
            behavior_class=behavior_class,
            supporting_evidence=supporting_refs,
            contradicting_evidence=contradicting_refs,
            tested_actions=tested_actions,
            updated_at=utcnow_iso(),
        )

    def verify(self, hypothesis: MissionHypothesis, *, reproducible: bool = True) -> MissionHypothesis:
        """Promote a supported hypothesis to VALIDATED after independent verification.

        ``reproducible=False`` keeps (or downgrades) the hypothesis at SUPPORTED:
        reproducibility is a first-class confidence component.
        """
        if hypothesis.state is not HypothesisState.SUPPORTED:
            return hypothesis
        if not reproducible:
            return replace(hypothesis, updated_at=utcnow_iso())
        return replace(
            hypothesis,
            state=HypothesisState.VALIDATED,
            updated_at=utcnow_iso(),
        )

    def prove(self, hypothesis: MissionHypothesis, *, proof_ref: str = "") -> MissionHypothesis:
        """Record proof on a validated hypothesis.

        Proof is only accepted when the hypothesis is already validated — a
        proof can never turn a candidate into a finding by itself.
        """
        if hypothesis.state is not HypothesisState.VALIDATED:
            return hypothesis
        return replace(
            hypothesis,
            state=HypothesisState.VALIDATED,
            proof_strategy=hypothesis.proof_strategy or "minimal-proof",
            updated_at=utcnow_iso(),
            provenance={**hypothesis.provenance, "proof_ref": proof_ref, "proved_at": utcnow_iso()},
        )

    # -- novel-vulnerability pipeline ---------------------------------------

    def advance_novel(
        self,
        record: NovelBehaviorRecord,
        *,
        stage: NovelPipelineStage | None = None,
        experiments: tuple[str, ...] = (),
        observations: tuple[str, ...] = (),
        hypothesis_id: str = "",
        proof_ref: str = "",
    ) -> NovelBehaviorRecord:
        """Advance a novel-behavior record through the experiment loop.

        Stage transitions are deterministic: UNKNOWN_BEHAVIOR → BEHAVIORAL_MODEL
        → HYPOTHESIS → EXPERIMENT → OBSERVATION → NEW_HYPOTHESIS → MINIMAL_PROOF
        → VALIDATED_BEHAVIOR.
        """
        new_stage = stage or _next_stage(record.stage)
        classification = record.classification
        if new_stage is NovelPipelineStage.VALIDATED_BEHAVIOR:
            classification = BehaviorClass.NOVEL_VALIDATED
        return replace(
            record,
            stage=new_stage,
            experiments=tuple(dict.fromkeys(record.experiments + experiments)),
            observations=tuple(dict.fromkeys(record.observations + observations)),
            hypothesis_id=hypothesis_id or record.hypothesis_id,
            proof_ref=proof_ref or record.proof_ref,
            classification=classification,
            updated_at=utcnow_iso(),
        )

    def start_novel(
        self,
        *,
        mission_id: str,
        asset_key: str,
        behavior_summary: str,
    ) -> NovelBehaviorRecord:
        """Open a novel-behavior record for unexplained behavior."""
        return NovelBehaviorRecord(
            record_id=generate_id(),
            mission_id=mission_id,
            asset_key=asset_key,
            stage=NovelPipelineStage.UNKNOWN_BEHAVIOR,
            behavior_summary=behavior_summary,
        )

    def hypothesize(
        self,
        *,
        mission_id: str,
        statement: str,
        category: HypothesisType = HypothesisType.UNKNOWN_BEHAVIOR,
        supporting: tuple[str, ...] = (),
        confidence: float = 0.4,
        priority: float = 0.5,
        validation_strategy: str = "",
        proof_strategy: str = "",
        behavior_class: BehaviorClass = BehaviorClass.NOVEL_CANDIDATE,
        proposed_by: str = "orchestrator",
    ) -> MissionHypothesis:
        """Create a fresh hypothesis (idempotent by statement per caller)."""
        return MissionHypothesis(
            hypothesis_id=generate_id(),
            mission_id=mission_id,
            statement=statement,
            category=category,
            state=HypothesisState.PROPOSED,
            behavior_class=behavior_class,
            supporting_evidence=tuple(supporting),
            confidence=confidence,
            priority=priority,
            validation_strategy=validation_strategy,
            proof_strategy=proof_strategy,
            proposed_by=proposed_by,
            provenance={"created_by": proposed_by},
        )


def _next_stage(stage: NovelPipelineStage) -> NovelPipelineStage:
    """Return the next stage in the novel pipeline."""
    order = [
        NovelPipelineStage.UNKNOWN_BEHAVIOR,
        NovelPipelineStage.BEHAVIORAL_MODEL,
        NovelPipelineStage.HYPOTHESIS,
        NovelPipelineStage.EXPERIMENT,
        NovelPipelineStage.OBSERVATION,
        NovelPipelineStage.NEW_HYPOTHESIS,
        NovelPipelineStage.MINIMAL_PROOF,
        NovelPipelineStage.VALIDATED_BEHAVIOR,
    ]
    if stage in order and order.index(stage) < len(order) - 1:
        return order[order.index(stage) + 1]
    return stage


def _classify_validated(behavior_class: BehaviorClass) -> BehaviorClass:
    """Promote a novel candidate to a validated novel behavior on validation."""
    if behavior_class is BehaviorClass.NOVEL_CANDIDATE:
        return BehaviorClass.NOVEL_VALIDATED
    return behavior_class


__all__ = [
    "HypothesisLoopEngine",
]
