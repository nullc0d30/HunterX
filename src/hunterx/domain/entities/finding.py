# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Finding entity.

A finding is a verified observation produced by a tool or engine. Findings are
normalized, deduplicated, correlated and scored before they become part of the
final report.

Sprint 028 extends the canonical finding with the orchestration fields
required by the autonomous vulnerability validation & proof lifecycle
(``vulnerability_class``, ``confidence``, affected assets/endpoints/parameters,
evidence/validation/proof/impact/reproduction references, scope and
provenance). The lifecycle status is tracked in ``lifecycle_status`` while the
legacy ``status`` free string is preserved for backward compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.domain.exceptions import InvalidFindingError
from hunterx.domain.value_objects import RiskScore, Severity
from hunterx.shared.ids import generate_content_id, generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class Finding(TidbEnvelopeMixin):
    """A normalized, deduplicated security observation.

    Attributes:
        title: short human-readable title.
        severity: canonical severity level.
        target: identifier of the affected target.
        tool: tool/plugin that produced the finding.
        mission_id: mission that produced the finding.
        description: detailed technical description.
        evidence_ids: identifiers of supporting evidence.
        references: external reference URLs.
        finding_id: stable identity (auto-generated).
        content_hash: deduplication hash derived from canonical fields.
        risk_score: optional normalized numeric score.
        metadata: free-form JSON-serializable attributes.
        status: legacy finding lifecycle status (TIDB).
        lifecycle_status: canonical orchestration lifecycle status.
        vulnerability_class: canonical vulnerability class.
        asset_id / target_id: scoping identifiers.
        confidence: evidence-driven confidence in ``[0, 1]``.
        affected_assets / affected_endpoints / affected_parameters: affected
            surface.
        observations: canonical normalized observations.
        evidence_refs / validation_refs / proof_refs / impact_refs /
        reproduction_refs: lifecycle reference lists.
        scope: scope context (JSON-safe).
        provenance: provenance of the finding.
        updated_at / first_seen / last_seen / version / revision /
        schema_version / deleted_at: TIDB envelope.

    """

    title: str
    severity: Severity
    target: str
    tool: str
    mission_id: str | None = None
    description: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    finding_id: str = field(default_factory=generate_id)
    content_hash: str = field(default_factory=str)
    risk_score: float | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)
    status: str = "new"
    lifecycle_status: str = "candidate"
    vulnerability_class: str = ""
    asset_id: str = ""
    target_id: str = ""
    confidence: float | None = None
    affected_assets: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    affected_parameters: list[str] = field(default_factory=list)
    observations: list[dict[str, object]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    validation_refs: list[str] = field(default_factory=list)
    proof_refs: list[str] = field(default_factory=list)
    impact_refs: list[str] = field(default_factory=list)
    reproduction_refs: list[str] = field(default_factory=list)
    scope: dict[str, object] = field(default_factory=dict)
    provenance: str = ""
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None

    def __post_init__(self) -> None:
        if not self.title:
            raise InvalidFindingError("finding title must not be empty.")
        if not self.target:
            raise InvalidFindingError("finding target must not be empty.")
        if not self.tool:
            raise InvalidFindingError("finding tool must not be empty.")
        if self.risk_score is not None and not 0.0 <= self.risk_score <= 10.0:
            raise InvalidFindingError("risk score must be in [0, 10].")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise InvalidFindingError("confidence must be in [0, 1].")

    @property
    def score(self) -> RiskScore:
        """The normalized risk score (defaults to severity-based proxy)."""
        if self.risk_score is not None:
            return RiskScore(self.risk_score)
        return RiskScore(float(self.severity))

    def compute_content_hash(self) -> str:
        """Compute and store the deduplication hash.

        The hash is based on the observation facts, not on identifiers, so
        re-runs of the same tool against the same target deduplicate.
        """
        self.content_hash = generate_content_id(
            self.tool, self.target, self.title, self.description, self.metadata
        )
        return self.content_hash
