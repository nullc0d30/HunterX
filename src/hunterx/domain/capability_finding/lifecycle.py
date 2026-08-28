# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Candidate lifecycle mapping and reproduction classification.

The Phase 6 lifecycle (Candidate -> Evidence -> Replay -> Reproduction ->
Impact Analysis -> PoC -> Validated Finding -> Report) is orchestrated on the
existing HunterX finding state machine — there is exactly one state machine,
and this module maps the Phase 6 stages onto it.
"""

from __future__ import annotations

from hunterx.domain.capability_finding.enums import ReproductionVerdict
from hunterx.domain.capability_finding.models import ReplayAttempt

#: Mapping of the Phase 6 spec stages onto the existing finding states.
PHASE_SIX_STAGES: dict[str, str] = {
    "candidate": "Candidate",
    "evidence_collected": "Evidence",
    "replaying": "Replay",
    "reproduced": "Reproduction",
    "impact_assessed": "Impact Analysis",
    "poc_generated": "PoC",
    "validated": "Validated Finding",
    "report_ready": "Report",
    "rejected": "Rejected",
}


def stage_for_state(state: str) -> str:
    """Return the Phase 6 spec stage for a finding state."""
    return PHASE_SIX_STAGES.get(state, state)


class ReproductionClassifier:
    """Classify a replay attempt series into a reproduction verdict."""

    def classify(self, attempts: tuple[ReplayAttempt, ...]) -> ReproductionVerdict:
        """Return the reproduction verdict for the attempt series.

        Every attempt must confirm the differential signal for
        ``REPRODUCIBLE``; a confirmed subset is ``INTERMITTENT``; no
        confirmation is ``NOT_REPRODUCIBLE``. An empty series is
        ``NOT_REPRODUCIBLE`` (no evidence of reproduction).
        """
        if not attempts:
            return ReproductionVerdict.NOT_REPRODUCIBLE
        confirmed = sum(1 for attempt in attempts if attempt.confirmed)
        if confirmed == len(attempts):
            return ReproductionVerdict.REPRODUCIBLE
        if confirmed > 0:
            return ReproductionVerdict.INTERMITTENT
        return ReproductionVerdict.NOT_REPRODUCIBLE


__all__ = ["PHASE_SIX_STAGES", "ReproductionClassifier", "stage_for_state"]
