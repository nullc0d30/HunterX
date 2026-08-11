# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report QA engine.

The QA engine checks the report before submission: missing fields,
unsupported claims, missing evidence, missing PoC where required, invalid
severity, invalid CVSS, invalid CWE, scope issues, secret leakage, PII
leakage, contradictions, duplicate findings, broken references, stale
evidence, unsupported impact and AI-hallucination indicators. Each check
returns PASS / FAIL / WARN; a report with a blocking FAIL can never become
``READY_FOR_SUBMISSION``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.reporting.enums import ClaimState, QaVerdict
from hunterx.domain.reporting.models import (
    QaCheckResult,
    ReportClaim,
    ReportDocument,
    ReportQaResult,
)

#: Candidate secrets and PII patterns detected during QA.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("api_key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-]{12,}")),
    ("password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s]{6,}")),
    ("token", re.compile(r"(?i)(token|bearer)\s*[:=]\s*[A-Za-z0-9_\-\.]{16,}")),
    ("secret", re.compile(r"(?i)(secret|client[_-]?secret)\s*[:=]\s*[A-Za-z0-9_\-]{12,}")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("cookie", re.compile(r"(?i)(sessionid|session_id|jsessionid|connect.sid)\s*=\s*[A-Za-z0-9_\-]{16,}")),
)

_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
)

#: Mandatory report fields.
_REQUIRED_FIELDS: tuple[str, ...] = (
    "report_id",
    "finding_id",
    "title",
    "severity",
    "classification",
    "qa",
    "evidence_bundle",
)

#: Valid severity values.
_VALID_SEVERITY = frozenset({"informational", "low", "medium", "high", "critical"})

#: Valid CWE identifier shape.
_CWE_RE = re.compile(r"^CWE-\d{1,4}$")

#: Valid CVSS version values.
_VALID_CVSS_VERSIONS = frozenset({"2.0", "3.0", "3.1", "4.0"})


@dataclass(frozen=True, slots=True)
class QaContext:
    """Context the QA engine needs beyond the report document.

    Attributes:
        verified_refs: identifiers of verified evidence/observations.
        stale_refs: identifiers of evidence considered stale.
        open_conflicts: number of open evidence conflicts.
        known_duplicates: finding identifiers known to be duplicates.

    """

    verified_refs: set[str] = field(default_factory=set)
    stale_refs: set[str] = field(default_factory=set)
    open_conflicts: int = 0
    known_duplicates: tuple[str, ...] = ()


class ReportQAEngine:
    """Deterministic report QA checker."""

    def check(
        self,
        document: ReportDocument,
        *,
        context: QaContext | None = None,
        text_content: str = "",
    ) -> ReportQaResult:
        """Run every QA check against ``document``.

        Args:
            document: the report document to check.
            context: verification context.
            text_content: rendered text content to scan for leaks.

        Returns:
            An aggregated :class:`ReportQaResult`.

        """
        context = context or QaContext()
        checks: list[QaCheckResult] = []
        payload = document.to_dict()

        checks.append(self._missing_fields(payload))
        checks.append(self._unsupported_claims(document.claims))
        checks.append(self._evidence_completeness(document))
        checks.append(self._poc_required(document))
        checks.append(self._severity_validity(document.severity.severity))
        checks.append(self._cvss_validity(document.classification.cvss.to_dict() if document.classification.cvss else None))
        checks.append(self._cwe_validity(document))
        checks.append(self._scope_validity(document))
        checks.append(self._secret_leakage(text_content))
        checks.append(self._pii_leakage(text_content))
        checks.append(self._contradictions(context.open_conflicts))
        checks.append(self._duplicates(document, context.known_duplicates))
        checks.append(self._broken_references(document, context.verified_refs))
        checks.append(self._stale_evidence(context.stale_refs))
        checks.append(self._unsupported_impact(document))
        checks.append(self._ai_hallucination(document))

        fails = [check for check in checks if check.verdict is QaVerdict.FAIL]
        warns = [check for check in checks if check.verdict is QaVerdict.WARN]
        blocked = any(check.blocking for check in checks if check.verdict is QaVerdict.FAIL)
        if fails:
            verdict = QaVerdict.FAIL
        elif warns:
            verdict = QaVerdict.WARN
        else:
            verdict = QaVerdict.PASS
        reasons = [f"{check.name}: {check.detail}" for check in fails]
        if not reasons and warns:
            reasons = [f"{check.name}: {check.detail}" for check in warns]
        if not reasons:
            reasons = ["all QA checks passed"]
        return ReportQaResult(
            report_id=document.report_id,
            verdict=verdict,
            checks=tuple(checks),
            blocked=blocked,
            reasons=tuple(reasons),
        )

    # -- individual checks ---------------------------------------------------

    def _missing_fields(self, payload: dict[str, Any]) -> QaCheckResult:
        missing = [name for name in _REQUIRED_FIELDS if name not in payload or payload.get(name) in (None, "", {})]
        if missing:
            return QaCheckResult("missing_fields", QaVerdict.FAIL, f"missing required fields: {', '.join(missing)}", True)
        return QaCheckResult("missing_fields", QaVerdict.PASS, "all required fields present")

    def _unsupported_claims(self, claims: tuple[ReportClaim, ...]) -> QaCheckResult:
        blocked = [claim.claim_text for claim in claims if claim.verification_state is ClaimState.BLOCKED]
        unsupported = [claim.claim_text for claim in claims if claim.verification_state is ClaimState.UNSUPPORTED]
        if blocked:
            return QaCheckResult(
                "unsupported_claims",
                QaVerdict.FAIL,
                f"blocked unsupported high-impact claims: {'; '.join(blocked)}",
                True,
            )
        if unsupported:
            return QaCheckResult(
                "unsupported_claims",
                QaVerdict.WARN,
                f"unsupported claims present: {'; '.join(unsupported)}",
            )
        return QaCheckResult("unsupported_claims", QaVerdict.PASS, "all claims supported or verified")

    def _evidence_completeness(self, document: ReportDocument) -> QaCheckResult:
        bundle = document.evidence_bundle
        artifacts = len(bundle.artifacts)
        if artifacts == 0:
            return QaCheckResult("evidence_completeness", QaVerdict.FAIL, "evidence bundle is empty", True)
        if artifacts < 2:
            return QaCheckResult("evidence_completeness", QaVerdict.WARN, "evidence bundle is thin")
        return QaCheckResult("evidence_completeness", QaVerdict.PASS, f"{artifacts} evidence artifacts referenced")

    def _poc_required(self, document: ReportDocument) -> QaCheckResult:
        if document.severity.severity in ("high", "critical") and document.poc is None:
            return QaCheckResult(
                "poc_required",
                QaVerdict.FAIL,
                "high/critical finding requires a PoC presentation",
                True,
            )
        return QaCheckResult("poc_required", QaVerdict.PASS, "PoC requirement satisfied")

    def _severity_validity(self, severity: str) -> QaCheckResult:
        if severity not in _VALID_SEVERITY:
            return QaCheckResult("severity_validity", QaVerdict.FAIL, f"invalid severity '{severity}'", True)
        return QaCheckResult("severity_validity", QaVerdict.PASS, f"severity '{severity}' is valid")

    def _cvss_validity(self, cvss: dict[str, Any] | None) -> QaCheckResult:
        if not cvss:
            return QaCheckResult("cvss_validity", QaVerdict.PASS, "no CVSS vector asserted")
        version = cvss.get("version")
        score = cvss.get("base_score")
        if version not in _VALID_CVSS_VERSIONS:
            return QaCheckResult("cvss_validity", QaVerdict.FAIL, f"invalid CVSS version '{version}'", True)
        if score is not None and not (0.0 <= float(score) <= 10.0):
            return QaCheckResult("cvss_validity", QaVerdict.FAIL, f"invalid CVSS base score '{score}'", True)
        return QaCheckResult("cvss_validity", QaVerdict.PASS, f"CVSS v{version} is valid")

    def _cwe_validity(self, document: ReportDocument) -> QaCheckResult:
        invalid = [cwe.cwe_id for cwe in document.classification.cwes if not _CWE_RE.match(cwe.cwe_id)]
        if invalid:
            return QaCheckResult("cwe_validity", QaVerdict.FAIL, f"invalid CWE identifiers: {', '.join(invalid)}", True)
        return QaCheckResult("cwe_validity", QaVerdict.PASS, "CWE mappings valid")

    def _scope_validity(self, document: ReportDocument) -> QaCheckResult:
        status = document.reportability.status.value
        if status in ("out_of_scope", "duplicate", "not_actionable"):
            return QaCheckResult("scope_validity", QaVerdict.FAIL, f"reportability verdict '{status}' blocks reporting", True)
        return QaCheckResult("scope_validity", QaVerdict.PASS, f"reportability verdict '{status}' is acceptable")

    def _secret_leakage(self, text: str) -> QaCheckResult:
        if not text:
            return QaCheckResult("secret_leakage", QaVerdict.PASS, "no text scanned")
        leaked = [name for name, pattern in _SECRET_PATTERNS if pattern.search(text)]
        if leaked:
            return QaCheckResult("secret_leakage", QaVerdict.FAIL, f"potential secret leakage: {', '.join(leaked)}", True)
        return QaCheckResult("secret_leakage", QaVerdict.PASS, "no secrets detected")

    def _pii_leakage(self, text: str) -> QaCheckResult:
        if not text:
            return QaCheckResult("pii_leakage", QaVerdict.PASS, "no text scanned")
        leaked = [name for name, pattern in _PII_PATTERNS if pattern.search(text)]
        if leaked:
            return QaCheckResult("pii_leakage", QaVerdict.FAIL, f"potential PII leakage: {', '.join(leaked)}", True)
        return QaCheckResult("pii_leakage", QaVerdict.PASS, "no PII detected")

    def _contradictions(self, open_conflicts: int) -> QaCheckResult:
        if open_conflicts > 0:
            return QaCheckResult(
                "contradictions",
                QaVerdict.FAIL,
                f"{open_conflicts} open evidence conflicts",
                True,
            )
        return QaCheckResult("contradictions", QaVerdict.PASS, "no open evidence conflicts")

    def _duplicates(self, document: ReportDocument, known_duplicates: tuple[str, ...]) -> QaCheckResult:
        if document.finding_id in known_duplicates:
            return QaCheckResult("duplicates", QaVerdict.FAIL, "finding is a known duplicate", True)
        return QaCheckResult("duplicates", QaVerdict.PASS, "no duplicate finding")

    def _broken_references(self, document: ReportDocument, verified_refs: set[str]) -> QaCheckResult:
        broken: list[str] = []
        for artifact in document.evidence_bundle.artifacts:
            if artifact.artifact_id in verified_refs:
                continue
            if artifact.content_hash and artifact.artifact_id not in verified_refs:
                broken.append(artifact.artifact_id)
        if broken:
            return QaCheckResult("broken_references", QaVerdict.WARN, f"unverified artifact references: {', '.join(broken[:3])}")
        return QaCheckResult("broken_references", QaVerdict.PASS, "all references resolvable")

    def _stale_evidence(self, stale_refs: set[str]) -> QaCheckResult:
        if stale_refs:
            return QaCheckResult("stale_evidence", QaVerdict.WARN, f"stale evidence referenced: {', '.join(sorted(stale_refs)[:3])}")
        return QaCheckResult("stale_evidence", QaVerdict.PASS, "evidence is fresh")

    def _unsupported_impact(self, document: ReportDocument) -> QaCheckResult:
        impact = document.impact
        if impact.any_impact() and not impact.evidence_refs and not impact.analyst_reasoned:
            return QaCheckResult(
                "unsupported_impact",
                QaVerdict.FAIL,
                "impact claimed without evidence or analyst reasoning",
                True,
            )
        return QaCheckResult("unsupported_impact", QaVerdict.PASS, "impact is evidence-backed")

    def _ai_hallucination(self, document: ReportDocument) -> QaCheckResult:
        """Flag hallucination indicators in AI-assisted content.

        A structural signal only: every claim is independently verified by the
        claim checker; this check flags claims whose confidence is implausibly
        high relative to the evidence backing.
        """
        inflated = [
            claim.claim_text
            for claim in document.claims
            if claim.verification_state is ClaimState.SUPPORTED
            and claim.confidence >= 1.0
            and not claim.source_refs
        ]
        if inflated:
            return QaCheckResult(
                "ai_hallucination",
                QaVerdict.WARN,
                f"claims carry unsupported high confidence: {'; '.join(inflated[:3])}",
            )
        return QaCheckResult("ai_hallucination", QaVerdict.PASS, "no hallucination indicators detected")


__all__ = ["QaContext", "ReportQAEngine"]
