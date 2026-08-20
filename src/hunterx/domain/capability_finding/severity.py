# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence-derived severity for validated findings.

Severity is never assumed: it is computed once from the candidate's retained
evidence (vulnerability class base, auth context, differential strength and
exploitation factors). Automatic ``CRITICAL`` is deliberately impossible —
criticality requires evidence of direct compromise (authenticated context,
exploitable class base and a strong differential), and even then the engine
caps at ``HIGH`` unless every factor is met.
"""

from __future__ import annotations

from hunterx.domain.capability_finding.models import CapabilityCandidate

#: Base severity per vulnerability class (conservative by design).
_CLASS_BASE: dict[str, str] = {
    "sql_injection": "high",
    "xss": "medium",
    "ssrf": "high",
    "ssti": "high",
    "lfi": "medium",
    "rfi": "high",
    "xxe": "high",
    "rce": "critical",
    "idor": "medium",
    "broken_access_control": "high",
    "authentication_flaws": "high",
    "command_injection": "high",
    "path_traversal": "medium",
    "open_redirect": "low",
    "csrf": "medium",
    "cors_misconfiguration": "medium",
    "security_misconfiguration": "medium",
    "host_header_injection": "medium",
    "http_request_smuggling": "high",
    "jwt_weakness": "high",
    "graphql_authorization": "high",
    "api_authorization": "high",
    "cloud_exposure": "high",
    "secret_exposure": "high",
    "known_cve": "high",
    "business_logic": "medium",
    "http_access_differential": "medium",
    "nosql_injection": "high",
    "authorization": "high",
    "authentication": "high",
    "api_security": "medium",
    "graphql_security": "medium",
    "sensitive_information_exposure": "medium",
    "known_vulnerable_component": "medium",
    "dependency_vulnerability": "medium",
    "unknown_behavior": "low",
}

_SEVERITY_LEVELS = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Differential signals that indicate direct exploitation (error-based or
#: reflection is stronger evidence than an HTTP-status or length delta).
_STRONG_SIGNALS = ("error", "reflection", "content")


class EvidenceSeverityEngine:
    """Compute a finding's severity from its candidate evidence."""

    def calculate(self, candidate: CapabilityCandidate) -> tuple[str, tuple[str, ...]]:
        """Return ``(severity, reasons)`` derived from the candidate evidence.

        Raises:
            ValueError: when the candidate class has no severity profile.

        """
        cls = candidate.finding_class
        if cls not in _CLASS_BASE:
            raise ValueError(f"no severity profile for class '{cls}'")
        base = _CLASS_BASE[cls]
        base_level = _SEVERITY_LEVELS[base]
        reasons: list[str] = [f"class base severity for {cls} is {base}"]

        level = base_level
        if candidate.session_state not in ("", "anonymous"):
            level += 1
            reasons.append("authenticated session expands the attack surface")

        signal = str(candidate.evidence.get("signal") or "")
        if any(strong in signal for strong in _STRONG_SIGNALS):
            level += 1
            reasons.append(f"observed differential signal '{signal}' indicates direct exploitation")
        else:
            reasons.append(f"observed differential signal '{signal or 'none'}' is indirect (status/length)")

        if candidate.evidence.get("content_signatures") or candidate.evidence.get("error_signatures"):
            level += 1
            reasons.append("response carries class-specific content/error signatures")
        else:
            level -= 1
            reasons.append("no class-specific content or error signature observed")

        if candidate.confidence is not None and candidate.confidence >= 0.85:
            level += 1
            reasons.append("high capability confidence")
        elif candidate.confidence is not None and candidate.confidence < 0.4:
            level -= 1
            reasons.append("low capability confidence")

        level = max(0, min(level, _SEVERITY_LEVELS["critical"]))
        if level >= _SEVERITY_LEVELS["critical"]:
            # Automatic critical is impossible: it requires a critical class
            # base (rce) plus every exploitation factor and a verified auth
            # context — and even then the confidence must be high.
            critical_ok = (
                base == "critical"
                and candidate.session_state not in ("", "anonymous")
                and any(strong in signal for strong in _STRONG_SIGNALS)
                and (candidate.confidence or 0.0) >= 0.85
            )
            if not critical_ok:
                level = _SEVERITY_LEVELS["high"]
                reasons.append("severity capped at high: automatic critical requires class base, exploited signal, auth context and high confidence")

        severity = next(name for name, value in _SEVERITY_LEVELS.items() if value == level)
        reasons.append(f"final severity: {severity}")
        return severity, tuple(reasons)


__all__ = ["EvidenceSeverityEngine"]
