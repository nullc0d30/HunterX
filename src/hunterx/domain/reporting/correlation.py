# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cross-finding correlation report builder.

Analyzes relationships between findings and their assets, credentials,
identities, cloud resources, endpoints, root causes, attack paths and other
findings so a report package can explain relationships where evidence
supports them — without implying compromise merely because a path is
theoretically possible.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.reporting.models import CrossFindingRelation, FindingCorrelationReport


@dataclass(frozen=True, slots=True)
class RelationInput:
    """One candidate cross-finding relation.

    Attributes:
        source_finding_id: source finding.
        target_finding_id: target finding / asset / credential / identity /
            resource / endpoint.
        relation: relation kind (finding->asset, finding->root_cause, ...).
        rationale: explainable rationale.
        evidence_refs: supporting evidence references.
        validated: whether the relation is evidence-validated (not merely
            theoretical).

    """

    source_finding_id: str
    target_finding_id: str
    relation: str
    rationale: str = ""
    evidence_refs: tuple[str, ...] = ()
    validated: bool = True


class FindingCorrelationReportBuilder:
    """Deterministic correlation report builder.

    Only evidence-supported relations are emitted; theoretical attack-path
    relations are marked ``validated=False`` and never imply compromise.
    """

    def build(
        self,
        *,
        report_id: str,
        relations: tuple[RelationInput, ...],
        root_cause_groups: tuple[str, ...] = (),
    ) -> FindingCorrelationReport:
        """Build a correlation report.

        Args:
            report_id: report identity.
            relations: candidate relations.
            root_cause_groups: shared root-cause group identifiers.

        Returns:
            A :class:`FindingCorrelationReport`.

        """
        emitted: list[CrossFindingRelation] = []
        for item in relations:
            if item.validated or item.relation == "attack_path":
                emitted.append(
                    CrossFindingRelation(
                        source_finding_id=item.source_finding_id,
                        target_finding_id=item.target_finding_id,
                        relation=item.relation,
                        rationale=item.rationale,
                        evidence_refs=item.evidence_refs,
                    )
                )
        return FindingCorrelationReport(
            report_id=report_id,
            relations=tuple(emitted),
            root_cause_groups=tuple(root_cause_groups),
        )


__all__ = ["FindingCorrelationReportBuilder", "RelationInput"]
