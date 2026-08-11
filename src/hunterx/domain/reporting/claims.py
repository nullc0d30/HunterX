# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Automated claim checking.

Before the final report: extract factual claims, resolve their sources,
verify them against evidence and block unsupported high-impact claims. The
report cannot become ``READY_FOR_SUBMISSION`` while an unsupported
high-impact claim is open.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.reporting.enums import ClaimState, ClaimType
from hunterx.domain.reporting.models import ReportClaim


@dataclass(frozen=True, slots=True)
class ClaimExtractor:
    """Extracts material claims from a report document."""

    def extract(self, document: dict[str, Any] | None) -> tuple[ReportClaim, ...]:
        """Extract the material claims of a report document.

        The extractor builds claims from the structured document data — never
        by parsing AI prose.

        Args:
            document: the report document mapping.

        Returns:
            A tuple of extracted :class:`ReportClaim` records.

        """
        claims: list[ReportClaim] = []
        if not document:
            return ()
        finding_id = str(document.get("finding_id") or "")
        severity = document.get("severity") or {}
        classification = document.get("classification") or {}
        impact = document.get("impact") or {}
        intelligence = document.get("intelligence") or {}

        if severity:
            severity_text = str(severity.get("severity") or "informational")
            bundle = intelligence.get("evidence_bundle") or {}
            severity_sources = tuple(
                item
                for item in (
                    *(bundle.get("validation_results") or ()),
                    *(bundle.get("proof_references") or ()),
                    *(bundle.get("replay_results") or ()),
                )
            )
            claims.append(
                ReportClaim(
                    claim_text=f"finding {finding_id} is rated {severity_text}",
                    source_refs=severity_sources,
                    claim_type=ClaimType.SEVERITY,
                    confidence=float(severity.get("evidence_backed", True)) if isinstance(severity.get("evidence_backed"), bool) else 1.0,
                    generated_by="hunterx.claims",
                )
            )

        for cwe in classification.get("cwes") or ():
            if isinstance(cwe, dict):
                claims.append(
                    ReportClaim(
                        claim_text=f"finding {finding_id} maps to {cwe.get('cwe_id')} ({cwe.get('title')})",
                        source_refs=(),
                        claim_type=ClaimType.CWE,
                        confidence=float(cwe.get("confidence") or 0.0),
                        generated_by="hunterx.claims",
                    )
                )
        for owasp in classification.get("owasp") or ():
            if isinstance(owasp, dict):
                claims.append(
                    ReportClaim(
                        claim_text=f"finding {finding_id} maps to {owasp.get('item_id')} ({owasp.get('title')})",
                        source_refs=(),
                        claim_type=ClaimType.OWASP,
                        confidence=float(owasp.get("confidence") or 0.0),
                        generated_by="hunterx.claims",
                    )
                )
        cvss = classification.get("cvss")
        if isinstance(cvss, dict) and cvss.get("base_score") is not None:
            claims.append(
                ReportClaim(
                    claim_text=f"finding {finding_id} CVSS base score is {cvss.get('base_score')} ({cvss.get('version')})",
                    source_refs=(),
                    claim_type=ClaimType.CVSS,
                    confidence=1.0,
                    generated_by="hunterx.claims",
                )
            )

        if impact:
            claims.append(
                ReportClaim(
                    claim_text=f"finding {finding_id} has evidence-backed business impact",
                    source_refs=(
                        *(bundle.get("validation_results") or ()),
                        *(bundle.get("replay_results") or ()),
                    ),
                    claim_type=ClaimType.BUSINESS_IMPACT,
                    confidence=1.0,
                    generated_by="hunterx.claims",
                )
            )

        # The core vulnerability claim is always present and must always be
        # verified against the finding state.
        bundle = intelligence.get("evidence_bundle") or {}
        claim_sources = tuple(
            item
            for item in (
                *(bundle.get("validation_results") or ()),
                *(bundle.get("proof_references") or ()),
                *(bundle.get("replay_results") or ()),
            )
        )
        claims.append(
            ReportClaim(
                claim_text=f"endpoint is vulnerable to {intelligence.get('vulnerability_class') or 'unknown'}",
                source_refs=claim_sources,
                claim_type=ClaimType.VULNERABILITY,
                confidence=float(intelligence.get("confidence") or 0.0),
                generated_by="hunterx.claims",
            )
        )
        return tuple(claims)


@dataclass(frozen=True, slots=True)

class ClaimVerifier:
    """Verifies claims against a verified-evidence index.

    A claim is ``SUPPORTED`` when it has at least one verified source
    reference; it is ``BLOCKED`` when it is a high-impact claim (vulnerability,
    severity, impact, CVSS) without any verified source.
    """

    #: Claim types that block the report when unsupported.
    _HIGH_IMPACT = frozenset(
        {
            ClaimType.VULNERABILITY,
            ClaimType.SEVERITY,
            ClaimType.IMPACT,
            ClaimType.CVSS,
            ClaimType.ROOT_CAUSE,
            ClaimType.AFFECTED_ASSET,
        }
    )

    def verify(
        self,
        claims: tuple[ReportClaim, ...],
        *,
        verified_refs: set[str],
    ) -> tuple[ReportClaim, ...]:
        """Verify ``claims`` against ``verified_refs``.

        Args:
            claims: claims to verify.
            verified_refs: identifiers of evidence/observations verified as
                authoritative (e.g. evidence ids, validation ids, replay ids).

        Returns:
            The claims with their verification state applied.

        """
        verified = []
        for claim in claims:
            if not claim.source_refs:
                state = ClaimState.UNSUPPORTED
                detail = "claim carries no source references"
            elif any(ref in verified_refs for ref in claim.source_refs):
                state = ClaimState.VERIFIED
                detail = "claim sources verified against evidence"
            else:
                state = ClaimState.UNSUPPORTED
                detail = "claim sources not present in the verified evidence index"
            if state is ClaimState.UNSUPPORTED and claim.claim_type in self._HIGH_IMPACT:
                state = ClaimState.BLOCKED
                detail = "unsupported high-impact claim blocked from submission"
            verified.append(
                ReportClaim(
                    claim_id=claim.claim_id,
                    claim_text=claim.claim_text,
                    source_refs=claim.source_refs,
                    claim_type=claim.claim_type,
                    confidence=claim.confidence,
                    generated_by=claim.generated_by,
                    verification_state=state,
                    verification_detail=detail,
                )
            )
        return tuple(verified)

    def blocked_claims(self, claims: tuple[ReportClaim, ...]) -> tuple[ReportClaim, ...]:
        """Return the claims that block the report from submission."""
        return tuple(claim for claim in claims if claim.verification_state is ClaimState.BLOCKED)


__all__ = ["ClaimExtractor", "ClaimVerifier"]
