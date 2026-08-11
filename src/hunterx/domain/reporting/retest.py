# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Retest plan engine.

Every actionable finding gets a retest plan that states what must change,
what endpoint/resource to test, what behavior should disappear, what proof
should fail, what evidence to collect and the acceptance criteria for fix
verification.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.models import RetestPlan


@dataclass(frozen=True, slots=True)
class RetestInput:
    """Inputs for the retest plan engine.

    Attributes:
        finding_id: owning finding.
        vulnerability_class: canonical class.
        endpoints: affected endpoints/resources to test.
        behavior: observed vulnerable behavior.
        proof_pocs: PoC identifiers whose replay should fail after the fix.
        evidence_refs: evidence references to re-collect.

    """

    finding_id: str = ""
    vulnerability_class: str = "unknown_behavior"
    endpoints: tuple[str, ...] = ()
    behavior: str = ""
    proof_pocs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()


class RetestPlanEngine:
    """Deterministic retest-plan builder."""

    def build(self, inp: RetestInput) -> RetestPlan:
        """Build a retest plan for ``inp``.

        Returns:
            An actionable :class:`RetestPlan`.

        """
        endpoints = inp.endpoints or ("the affected endpoint",)
        behavior = inp.behavior or f"the {inp.vulnerability_class or 'vulnerable'} behavior"
        return RetestPlan(
            finding_id=inp.finding_id,
            what_must_change=(f"the root cause of {behavior} must be fixed",),
            endpoints=endpoints,
            behaviors_to_disappear=(f"{behavior} must no longer be observable",),
            proofs_to_fail=tuple(
                f"PoC {poc_id} replay must fail (proof no longer reproducible)" for poc_id in inp.proof_pocs
            )
            or (f"the {inp.vulnerability_class or 'original'} proof replay must fail",),
            evidence_to_collect=(
                "replay records for each original PoC",
                "response/behavior evidence showing the vulnerable behavior is gone",
                "authorization/scope verification for the retest run",
            ),
            acceptance_criteria=(
                "the original PoC no longer reproduces the vulnerable behavior",
                "the controlled callback / differential evidence no longer fires",
                "the affected endpoint returns expected, non-vulnerable behavior under the same conditions",
            ),
            created_at=_now(),
        )


def _now() -> str:
    """Return the current UTC ISO-8601 timestamp."""
    from hunterx.shared.time import utcnow_iso

    return utcnow_iso()


__all__ = ["RetestPlanEngine", "RetestInput"]
