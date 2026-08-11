# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report lifecycle state machine.

The report lifecycle is explicit: every transition between report states is
gated. ``READY_FOR_SUBMISSION`` is only reachable after QA passed and no
unsupported high-impact claim is open.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.reporting.enums import QaVerdict, ReportState


@dataclass(frozen=True, slots=True)
class ReportStateTransition:
    """Allowed source/target state transition.

    Attributes:
        from_state: source state.
        to_state: target state.
        reason: why the transition is allowed.
        gated: whether the transition requires an explicit gate condition.

    """

    from_state: ReportState
    to_state: ReportState
    reason: str
    gated: bool = False


@dataclass(frozen=True, slots=True)
class StateTransitionResult:
    """Result of a requested state transition.

    Attributes:
        from_state: source state.
        to_state: requested target state.
        allowed: whether the transition was granted.
        reason: explainable reason.
        missing_gates: gate conditions that blocked the transition.
        transitioned_at: UTC ISO-8601 transition timestamp.

    """

    from_state: ReportState
    to_state: ReportState
    allowed: bool
    reason: str = ""
    missing_gates: tuple[str, ...] = ()
    transitioned_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe mapping."""
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "missing_gates": list(self.missing_gates),
            "transitioned_at": self.transitioned_at,
        }


class ReportStateMachine:
    """Deterministic report lifecycle state machine.

    Every meaningful transition between report states is declared; the
    ``transition`` method refuses unknown transitions and reports the missing
    gates (QA passed, no unsupported claims, redaction applied) for gated
    transitions.
    """

    def __init__(self) -> None:
        self._transitions: dict[tuple[ReportState, ReportState], ReportStateTransition] = {
            (ReportState.DRAFT, ReportState.EVIDENCE_REVIEW): ReportStateTransition(
                ReportState.DRAFT,
                ReportState.EVIDENCE_REVIEW,
                "evidence assembled for review",
            ),
            (ReportState.EVIDENCE_REVIEW, ReportState.ANALYSIS_COMPLETE): ReportStateTransition(
                ReportState.EVIDENCE_REVIEW,
                ReportState.ANALYSIS_COMPLETE,
                "analysis (severity/quality/classification) completed",
            ),
            (ReportState.ANALYSIS_COMPLETE, ReportState.REPORTABLE): ReportStateTransition(
                ReportState.ANALYSIS_COMPLETE,
                ReportState.REPORTABLE,
                "reportability verdict is REPORTABLE",
                gated=True,
            ),
            (ReportState.REPORTABLE, ReportState.REPORT_GENERATED): ReportStateTransition(
                ReportState.REPORTABLE,
                ReportState.REPORT_GENERATED,
                "report content generated from a consistent snapshot",
            ),
            (ReportState.REPORT_GENERATED, ReportState.QA_REQUIRED): ReportStateTransition(
                ReportState.REPORT_GENERATED,
                ReportState.QA_REQUIRED,
                "generated report queued for QA",
            ),
            (ReportState.QA_REQUIRED, ReportState.QA_PASSED): ReportStateTransition(
                ReportState.QA_REQUIRED,
                ReportState.QA_PASSED,
                "QA passed with no blocking check",
                gated=True,
            ),
            (ReportState.QA_REQUIRED, ReportState.QA_FAILED): ReportStateTransition(
                ReportState.QA_REQUIRED,
                ReportState.QA_FAILED,
                "QA found blocking defects",
                gated=True,
            ),
            (ReportState.QA_FAILED, ReportState.REPORT_GENERATED): ReportStateTransition(
                ReportState.QA_FAILED,
                ReportState.REPORT_GENERATED,
                "regenerated after QA feedback",
            ),
            (ReportState.QA_PASSED, ReportState.READY_FOR_SUBMISSION): ReportStateTransition(
                ReportState.QA_PASSED,
                ReportState.READY_FOR_SUBMISSION,
                "QA passed and no unsupported high-impact claim is open",
                gated=True,
            ),
            (ReportState.READY_FOR_SUBMISSION, ReportState.SUBMITTED): ReportStateTransition(
                ReportState.READY_FOR_SUBMISSION,
                ReportState.SUBMITTED,
                "report submitted to the recipient",
            ),
            (ReportState.SUBMITTED, ReportState.REOPENED): ReportStateTransition(
                ReportState.SUBMITTED,
                ReportState.REOPENED,
                "finding reopened after submission",
            ),
            (ReportState.REOPENED, ReportState.REPORT_GENERATED): ReportStateTransition(
                ReportState.REOPENED,
                ReportState.REPORT_GENERATED,
                "regenerated for a reopened finding",
            ),
            (ReportState.REPORT_GENERATED, ReportState.REMEDIATED): ReportStateTransition(
                ReportState.REPORT_GENERATED,
                ReportState.REMEDIATED,
                "remediation applied",
            ),
            (ReportState.REMEDIATED, ReportState.RETESTED): ReportStateTransition(
                ReportState.REMEDIATED,
                ReportState.RETESTED,
                "retest executed",
            ),
            (ReportState.SUBMITTED, ReportState.CLOSED): ReportStateTransition(
                ReportState.SUBMITTED,
                ReportState.CLOSED,
                "report closed",
            ),
            (ReportState.RETESTED, ReportState.CLOSED): ReportStateTransition(
                ReportState.RETESTED,
                ReportState.CLOSED,
                "retested report closed",
            ),
        }

    def can_transition(self, from_state: ReportState, to_state: ReportState) -> bool:
        """Return ``True`` when the transition is declared."""
        return (from_state, to_state) in self._transitions

    def allowed_transitions(self, from_state: ReportState) -> tuple[ReportState, ...]:
        """Return the declared target states for ``from_state``."""
        return tuple(
            target
            for (source, target) in self._transitions
            if source is from_state
        )

    def transition(
        self,
        from_state: ReportState,
        to_state: ReportState,
        *,
        qa_passed: bool = False,
        no_unsupported_claims: bool = False,
        redaction_applied: bool = False,
        transitioned_at: str = "",
    ) -> StateTransitionResult:
        """Request a state transition.

        Args:
            from_state: current report state.
            to_state: requested target state.
            qa_passed: whether QA passed (required for QA_PASSED /
                READY_FOR_SUBMISSION).
            no_unsupported_claims: whether no unsupported high-impact claim is
                open (required for READY_FOR_SUBMISSION).
            redaction_applied: whether redaction was applied (required for
                READY_FOR_SUBMISSION).
            transitioned_at: optional explicit transition timestamp.

        Returns:
            A :class:`StateTransitionResult` describing the outcome.

        """
        from hunterx.shared.time import utcnow_iso

        transition = self._transitions.get((from_state, to_state))
        if transition is None:
            return StateTransitionResult(
                from_state=from_state,
                to_state=to_state,
                allowed=False,
                reason=f"transition {from_state.value} -> {to_state.value} is not declared",
                transitioned_at=transitioned_at or utcnow_iso(),
            )
        missing: list[str] = []
        if to_state in (ReportState.QA_PASSED, ReportState.READY_FOR_SUBMISSION) and not qa_passed:
            missing.append("qa_passed")
        if to_state is ReportState.READY_FOR_SUBMISSION and not no_unsupported_claims:
            missing.append("no_unsupported_claims")
        if to_state is ReportState.READY_FOR_SUBMISSION and not redaction_applied:
            missing.append("redaction_applied")
        if missing:
            return StateTransitionResult(
                from_state=from_state,
                to_state=to_state,
                allowed=False,
                reason=f"transition gated by: {', '.join(missing)}",
                missing_gates=tuple(missing),
                transitioned_at=transitioned_at or utcnow_iso(),
            )
        return StateTransitionResult(
            from_state=from_state,
            to_state=to_state,
            allowed=True,
            reason=transition.reason,
            transitioned_at=transitioned_at or utcnow_iso(),
        )

    def required_for_submission(self, qa_result: Any | None = None) -> tuple[str, ...]:
        """Return the gates required for ``READY_FOR_SUBMISSION``.

        When a ``qa_result`` is provided, the verdict is included in the
        evaluation.
        """
        gates: list[str] = ["qa_passed", "no_unsupported_claims", "redaction_applied"]
        if qa_result is not None and getattr(qa_result, "verdict", None) is QaVerdict.PASS:
            return tuple(gates)
        if qa_result is not None and getattr(qa_result, "verdict", None) is QaVerdict.FAIL:
            return tuple([*gates, "qa_fail_blocked"])
        return tuple(gates)


__all__ = [
    "ReportStateMachine",
    "ReportStateTransition",
    "StateTransitionResult",
]
