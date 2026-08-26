# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security Test Matrix — the mission completion contract.

For ``full_security_assessment`` the matrix is the authoritative record of
which security-testing domains are applicable to the target and whether each
has been genuinely assessed. It replaces queue-exhaustion as the completion
signal:

* Every domain carries :class:`MatrixState`; only these are terminal:

  - ``TESTED_NEGATIVE``              (actively tested, no vulnerability found)
  - ``TESTED_POSITIVE_VALIDATED``    (vulnerability validated with evidence)
  - ``NOT_APPLICABLE_WITH_EVIDENCE`` (deterministic evidence shows the domain
    cannot apply, e.g. no GraphQL endpoint exists)
  - ``BLOCKED_WITH_REASON``          (explicitly impossible now, with reason)

* ``NOT_ASSESSED``, ``IN_PROGRESS`` and ``DEFERRED`` are NEVER terminal: the
  mission cannot claim completion while an applicable domain sits in one of
  them.

* Hypotheses do NOT drive the matrix — the matrix drives the assessment. A
  domain requires testing even when no hypothesis currently exists.

The matrix is updated deterministically from real capability executions
(evidence-backed bookkeeping); the AI Hunt Director reads it every cycle and
selects the next domain to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MatrixState(str, Enum):
    """Lifecycle state of one security-testing domain."""

    NOT_ASSESSED = "not_assessed"
    IN_PROGRESS = "in_progress"
    DEFERRED = "deferred"
    TESTED_NEGATIVE = "tested_negative"
    TESTED_POSITIVE_VALIDATED = "tested_positive_validated"
    NOT_APPLICABLE_WITH_EVIDENCE = "not_applicable_with_evidence"
    BLOCKED_WITH_REASON = "blocked_with_reason"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` only for honest terminal states."""
        return self in _TERMINAL_STATES


_TERMINAL_STATES = frozenset(
    {
        MatrixState.TESTED_NEGATIVE,
        MatrixState.TESTED_POSITIVE_VALIDATED,
        MatrixState.NOT_APPLICABLE_WITH_EVIDENCE,
        MatrixState.BLOCKED_WITH_REASON,
    }
)

#: Categories used for truthful, separated coverage metrics.
CATEGORY_RECONNAISSANCE = "reconnaissance"
CATEGORY_ATTACK_SURFACE = "attack_surface"
CATEGORY_ACTIVE_TESTING = "active_testing"
CATEGORY_VALIDATION = "validation"
CATEGORY_ANALYSIS = "analysis"


@dataclass(slots=True)
class MatrixDomain:
    """One assessable security-testing domain."""

    domain: str
    label: str
    category: str
    #: Capability ids whose successful execution satisfies this domain.
    capabilities: tuple[str, ...] = ()
    #: Domain applies only when one of these markers is present in the target
    #: context (empty = always applicable for the target kind).
    requires_markers: tuple[str, ...] = ()
    applicability: str = "applicable"  # applicable | not_applicable | unknown
    applicability_evidence: str = ""
    status: MatrixState = MatrixState.NOT_ASSESSED
    reason: str = ""
    tests: list[dict[str, Any]] = field(default_factory=list)
    tools_used: set[str] = field(default_factory=set)
    evidence_count: int = 0
    findings: int = 0
    validated_findings: int = 0
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "label": self.label,
            "category": self.category,
            "capabilities": list(self.capabilities),
            "applicability": self.applicability,
            "applicability_evidence": self.applicability_evidence,
            "status": self.status.value,
            "terminal": self.status.is_terminal,
            "reason": self.reason,
            "tests": len(self.tests),
            "tools_used": sorted(self.tools_used),
            "evidence_count": self.evidence_count,
            "findings": self.findings,
            "validated_findings": self.validated_findings,
            "blocked_reason": self.blocked_reason,
        }


def _web_domains() -> list[MatrixDomain]:
    """The canonical web-application security-testing domain set.

    This is the *completion contract*, not an execution plan: the AI decides
    which capability/test satisfies each domain and in which order.
    """
    return [
        MatrixDomain("reconnaissance", "Reconnaissance & service discovery", CATEGORY_RECONNAISSANCE,
                     ("asset_discovery", "subdomain_enumeration", "dns_enumeration", "port_discovery", "service_detection")),
        MatrixDomain("attack_surface_discovery", "Attack-surface & endpoint discovery", CATEGORY_ATTACK_SURFACE,
                     ("endpoint_enumeration", "content_discovery", "javascript_analysis", "api_mapping")),
        MatrixDomain("technology_fingerprinting", "Technology fingerprinting", CATEGORY_ATTACK_SURFACE,
                     ("technology_fingerprint",)),
        MatrixDomain("parameter_discovery", "Parameter & input discovery", CATEGORY_ATTACK_SURFACE,
                     ("parameter_discovery",)),
        MatrixDomain("authentication", "Authentication", CATEGORY_ACTIVE_TESTING,
                     ("authentication_analysis",)),
        MatrixDomain("session_management", "Session management", CATEGORY_ACTIVE_TESTING,
                     ("authentication_analysis",)),
        MatrixDomain("authorization_idor", "Authorization / IDOR / BOLA", CATEGORY_ACTIVE_TESTING,
                     ("authorization_analysis", "idor")),
        MatrixDomain("sql_injection", "SQL injection", CATEGORY_ACTIVE_TESTING,
                     ("sql_injection",)),
        MatrixDomain("nosql_injection", "NoSQL injection", CATEGORY_ACTIVE_TESTING,
                     ("sql_injection",)),
        MatrixDomain("command_injection", "Command injection / RCE", CATEGORY_ACTIVE_TESTING,
                     ("rce",)),
        MatrixDomain("template_injection", "Template injection (SSTI)", CATEGORY_ACTIVE_TESTING,
                     ("ssti",)),
        MatrixDomain("xss", "Cross-site scripting (XSS)", CATEGORY_ACTIVE_TESTING,
                     ("xss",)),
        MatrixDomain("ssrf", "Server-side request forgery (SSRF)", CATEGORY_ACTIVE_TESTING,
                     ("ssrf",)),
        MatrixDomain("xxe", "XML external entities (XXE)", CATEGORY_ACTIVE_TESTING,
                     ("xxe",),
                     requires_markers=("xml",)),
        MatrixDomain("path_traversal_lfi", "Path traversal / file inclusion", CATEGORY_ACTIVE_TESTING,
                     ("lfi",)),
        MatrixDomain("file_upload", "File upload", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",),
                     requires_markers=("upload",)),
        MatrixDomain("api_security", "API security", CATEGORY_ACTIVE_TESTING,
                     ("api_security",),
                     requires_markers=("api",)),
        MatrixDomain("http_methods", "HTTP methods & access control", CATEGORY_ACTIVE_TESTING,
                     ("http_access_differential", "vulnerability_scanning")),
        MatrixDomain("security_headers", "Security headers & misconfiguration", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("cors", "CORS policy", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("csrf", "CSRF", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("open_redirect", "Open redirect", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("business_logic", "Business logic", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("rate_limiting", "Rate limiting & brute-force protection", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("input_validation", "Input validation", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",)),
        MatrixDomain("client_side_security", "Client-side security", CATEGORY_ACTIVE_TESTING,
                     ("javascript_analysis",)),
        MatrixDomain("browser_testing", "Browser-based testing", CATEGORY_ACTIVE_TESTING,
                     ("browser_testing",)),
        MatrixDomain("sensitive_data_exposure", "Sensitive-data exposure & secrets", CATEGORY_ACTIVE_TESTING,
                     ("secret_detection",)),
        MatrixDomain("information_disclosure", "Information disclosure", CATEGORY_ACTIVE_TESTING,
                     ("content_discovery", "secret_detection", "vulnerability_scanning")),
        MatrixDomain("jwt_security", "JWT / token security", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",),
                     requires_markers=("jwt",)),
        MatrixDomain("graphql_testing", "GraphQL security", CATEGORY_ACTIVE_TESTING,
                     ("graphql_security",),
                     requires_markers=("graphql",)),
        MatrixDomain("websocket_testing", "WebSocket security", CATEGORY_ACTIVE_TESTING,
                     ("vulnerability_scanning",),
                     requires_markers=("websocket",)),
        MatrixDomain("attack_path_analysis", "Attack-path analysis", CATEGORY_ANALYSIS,
                     ()),
        MatrixDomain("validation", "Finding validation", CATEGORY_VALIDATION,
                     ()),
        MatrixDomain("proof_generation", "Proof / PoC generation", CATEGORY_VALIDATION,
                     ("proof_validation", "replay")),
    ]


class SecurityTestMatrix:
    """First-class security test matrix for one mission."""

    def __init__(self, *, target_kind: str = "web") -> None:
        self.target_kind = target_kind
        self.domains: dict[str, MatrixDomain] = {d.domain: d for d in _web_domains()}

    # -- applicability -------------------------------------------------------

    def update_applicability(self, context_markers: set[str], *, is_web: bool = True) -> list[str]:
        """Re-evaluate domain applicability from discovered target context.

        Returns the ids of domains whose applicability changed. Conditional
        domains whose markers were never observed after the attack surface has
        been enumerated become ``NOT_APPLICABLE_WITH_EVIDENCE`` — the evidence
        being the enumerated surface itself.
        """
        changed: list[str] = []
        for domain in self.domains.values():
            if not domain.requires_markers:
                continue
            matched = any(marker in context_markers for marker in domain.requires_markers)
            new_applicability = "applicable" if matched else "not_applicable"
            if matched and domain.applicability != "applicable":
                domain.applicability = "applicable"
                if domain.status is MatrixState.NOT_ASSESSED:
                    domain.status = MatrixState.NOT_ASSESSED
                changed.append(domain.domain)
            elif not matched and domain.applicability == "applicable" and domain.status is MatrixState.NOT_ASSESSED:
                domain.applicability = new_applicability
                domain.status = MatrixState.NOT_APPLICABLE_WITH_EVIDENCE
                domain.applicability_evidence = (
                    "no " + "/".join(domain.requires_markers) + " surface observed in the enumerated target context"
                )
                domain.reason = domain.applicability_evidence
                changed.append(domain.domain)
        return changed

    # -- recording -----------------------------------------------------------

    def record_execution(
        self,
        *,
        capability: str,
        tool_id: str,
        outcome: str,
        findings: int = 0,
        validated_findings: int = 0,
        notes: str = "",
    ) -> list[str]:
        """Record a real capability execution against every matching domain.

        ``outcome`` ∈ tested_positive | tested_negative | uninformative | failed.
        Returns the domain ids updated.
        """
        updated: list[str] = []
        for domain in self.domains.values():
            if capability and capability not in domain.capabilities:
                continue
            if domain.status is MatrixState.BLOCKED_WITH_REASON:
                continue
            touched = False
            if tool_id:
                domain.tools_used.add(tool_id)
                touched = True
            if outcome in ("tested_positive", "tested_negative"):
                domain.evidence_count += 1
                domain.findings += findings
                domain.validated_findings += validated_findings
                domain.tests.append(
                    {
                        "capability": capability,
                        "tool_id": tool_id,
                        "outcome": outcome,
                        "findings": findings,
                        "validated": validated_findings,
                        "notes": notes[:200],
                    }
                )
                if validated_findings > 0:
                    domain.status = MatrixState.TESTED_POSITIVE_VALIDATED
                    domain.reason = f"{validated_findings} validated finding(s)"
                else:
                    domain.status = MatrixState.TESTED_NEGATIVE
                    domain.reason = notes[:200] or f"tested via {capability} ({tool_id or 'in-process'})"
                touched = True
            elif outcome == "uninformative" and domain.status is MatrixState.NOT_ASSESSED:
                domain.status = MatrixState.IN_PROGRESS
                domain.reason = notes[:200] or f"{capability} produced no usable signal yet"
                touched = True
            elif outcome == "failed" and domain.status is MatrixState.NOT_ASSESSED:
                domain.status = MatrixState.IN_PROGRESS
                domain.reason = notes[:200] or f"{capability} execution failed"
                touched = True
            if touched:
                updated.append(domain.domain)
        return updated

    def record_validated_finding(self, capability: str) -> list[str]:
        """Promote matching domains to positive-validated (evidence-backed)."""
        updated: list[str] = []
        for domain in self.domains.values():
            if capability in domain.capabilities:
                domain.validated_findings += 1
                domain.findings += 1
                domain.evidence_count += 1
                domain.status = MatrixState.TESTED_POSITIVE_VALIDATED
                domain.reason = "validated finding recorded"
                updated.append(domain.domain)
        return updated

    def mark_blocked(self, domain_id: str, reason: str) -> bool:
        """Explicitly block a domain (browser unavailable, tool missing, ...)."""
        domain = self.domains.get(domain_id)
        if domain is None:
            return False
        if domain.status.is_terminal and domain.status is not MatrixState.BLOCKED_WITH_REASON:
            return False
        domain.status = MatrixState.BLOCKED_WITH_REASON
        domain.blocked_reason = reason
        domain.reason = reason
        return True

    def mark_tested_negative(self, domain_id: str, reason: str) -> bool:
        """Mark a domain honestly negative after genuine testing."""
        domain = self.domains.get(domain_id)
        if domain is None:
            return False
        if domain.status is MatrixState.TESTED_POSITIVE_VALIDATED:
            return False
        domain.status = MatrixState.TESTED_NEGATIVE
        domain.reason = reason
        return True

    # -- queries -------------------------------------------------------------

    def domain(self, domain_id: str) -> MatrixDomain | None:
        return self.domains.get(domain_id)

    def applicable_domains(self) -> list[MatrixDomain]:
        return [d for d in self.domains.values() if d.applicability == "applicable"]

    def incomplete_domains(self) -> list[MatrixDomain]:
        """Applicable domains not in a terminal state."""
        return [
            d
            for d in self.applicable_domains()
            if not d.status.is_terminal
        ]

    def pending_domain_ids(self) -> list[str]:
        """Applicable, still-untested domain ids ordered for planning."""
        priority = {MatrixState.IN_PROGRESS: 0, MatrixState.NOT_ASSESSED: 1, MatrixState.DEFERRED: 2}
        domains = [d for d in self.incomplete_domains()]
        domains.sort(key=lambda d: (priority.get(d.status, 3), -len(d.capabilities)))
        return [d.domain for d in domains]

    def is_complete(self) -> bool:
        """Return ``True`` when every applicable domain reached a terminal state."""
        return not self.incomplete_domains()

    def capabilities_for_domain(self, domain_id: str) -> tuple[str, ...]:
        domain = self.domains.get(domain_id)
        return domain.capabilities if domain else ()

    def domains_for_capability(self, capability: str) -> list[str]:
        return [
            d.domain
            for d in self.domains.values()
            if capability in d.capabilities
        ]

    # -- metrics -------------------------------------------------------------

    def coverage_by_category(self) -> dict[str, dict[str, float]]:
        """Truthful, separated coverage per category (never aggregated away)."""
        report: dict[str, dict[str, float]] = {}
        for category in (CATEGORY_RECONNAISSANCE, CATEGORY_ATTACK_SURFACE, CATEGORY_ACTIVE_TESTING, CATEGORY_VALIDATION, CATEGORY_ANALYSIS):
            domains = [d for d in self.domains.values() if d.category == category]
            applicable = [d for d in domains if d.applicability == "applicable"]
            tested = [
                d
                for d in applicable
                if d.status in (MatrixState.TESTED_NEGATIVE, MatrixState.TESTED_POSITIVE_VALIDATED)
            ]
            terminal = [d for d in applicable if d.status.is_terminal]
            report[category] = {
                "domains": float(len(domains)),
                "applicable": float(len(applicable)),
                "actively_tested": float(len(tested)),
                "terminal": float(len(terminal)),
                "coverage_ratio": round(len(terminal) / len(applicable), 4) if applicable else 1.0,
                "active_testing_ratio": round(len(tested) / len(applicable), 4) if applicable else 1.0,
            }
        return report

    def summary(self) -> dict[str, Any]:
        applicable = self.applicable_domains()
        incomplete = self.incomplete_domains()
        return {
            "target_kind": self.target_kind,
            "total_domains": len(self.domains),
            "applicable_domains": len(applicable),
            "terminal_domains": len(applicable) - len(incomplete),
            "incomplete_domains": [d.domain for d in incomplete],
            "complete": self.is_complete(),
            "coverage_by_category": self.coverage_by_category(),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.summary()
        payload["domains"] = [d.to_dict() for d in self.domains.values()]
        return payload


__all__ = [
    "MatrixDomain",
    "MatrixState",
    "SecurityTestMatrix",
    "CATEGORY_ACTIVE_TESTING",
    "CATEGORY_ATTACK_SURFACE",
    "CATEGORY_RECONNAISSANCE",
    "CATEGORY_VALIDATION",
]
