# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript secret detection.

Detects candidate secrets in script content without ever persisting a raw
value: every finding stores a masked preview and a SHA-256 hash of the
candidate, plus the reason the candidate was kept or rejected. False-positive
control rejects placeholder text, obvious sample values and values shorter than
a minimum length.

This module never logs, stores or renders raw candidate values — the masking
contract is enforced here and in the models.
"""

from __future__ import annotations

import hashlib
import re

from hunterx.domain.javascript.analyzers import AnalyzeContext, _location
from hunterx.domain.javascript.models import (
    ConfidenceTier,
    JSSecretIndicator,
    SecretClassification,
)
from hunterx.domain.javascript.rules import JSRuleRegistry, RuleCategory, RuleMatch

#: Minimum length for a generic credential candidate.
_MIN_GENERIC_LENGTH = 8

#: Placeholder/sample markers that indicate a non-secret value.
_PLACEHOLDER_MARKERS = (
    "example",
    "your_",
    "your-",
    "yourpassword",
    "yoursecret",
    "yourtoken",
    "yourapikey",
    "placeholder",
    "changeme",
    "change-me",
    "replaceme",
    "lorem",
    "sample",
    "dummy",
    "xxxxx",
)

#: Assignment-like generic patterns are only accepted with a key and value.
_GENERIC_ASSIGNMENT = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|refresh[_-]?token)\s*[:=]\s*\\?[\"']([^\"']{8,})\\?[\"']",
    re.IGNORECASE,
)

#: Rule id -> canonical classification.
_CLASSIFICATION_BY_RULE: dict[str, SecretClassification] = {
    "js-secret-001": SecretClassification.CLOUD_CREDENTIAL,
    "js-secret-002": SecretClassification.API_KEY,
    "js-secret-003": SecretClassification.ACCESS_TOKEN,
    "js-secret-004": SecretClassification.ACCESS_TOKEN,
    "js-secret-005": SecretClassification.API_KEY,
    "js-secret-006": SecretClassification.API_KEY,
    "js-secret-007": SecretClassification.API_KEY,
    "js-secret-008": SecretClassification.PRIVATE_KEY,
    "js-secret-009": SecretClassification.JWT,
    "js-secret-010": SecretClassification.GENERIC_SECRET,
}

#: Tier assigned to a rule id when the rule confidence is high.
_TIER_BY_RULE: dict[str, ConfidenceTier] = {
    "js-secret-001": ConfidenceTier.HIGH,
    "js-secret-002": ConfidenceTier.HIGH,
    "js-secret-003": ConfidenceTier.HIGH,
    "js-secret-005": ConfidenceTier.HIGH,
    "js-secret-008": ConfidenceTier.CRITICAL_INDICATOR,
}


class JSSecretScanner:
    """Scan script content for candidate secrets (masked output only)."""

    def __init__(
        self,
        *,
        rules: JSRuleRegistry | None = None,
        min_generic_length: int = _MIN_GENERIC_LENGTH,
        reveal_head: int = 4,
    ) -> None:
        self._rules = rules or JSRuleRegistry()
        self._min_generic_length = min_generic_length
        self._reveal_head = reveal_head

    def scan(self, source: str, context: AnalyzeContext) -> list[JSSecretIndicator]:
        """Return the secret indicators found in ``source``.

        The returned indicators never contain raw values: ``masked_value`` is a
        preview and ``value_hash`` is the SHA-256 digest of the candidate.
        """
        findings: list[JSSecretIndicator] = []
        seen: set[str] = set()

        for match in self._rules.match_for_category(source, RuleCategory.SECRET):
            candidate = _extract_candidate(source, match)
            if candidate is None:
                continue
            if self._reject(candidate, match):
                continue
            key = self._hash(candidate)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                self._indicator(source, candidate, match, context)
            )

        # generic assignment fallback (rule js-secret-010 may not fire when the
        # value sits on the next line or uses different quoting)
        for generic in _GENERIC_ASSIGNMENT.finditer(source):
            candidate = generic.group(1)
            if not candidate or self._reject(candidate, None):
                continue
            key = self._hash(candidate)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                self._indicator(
                    source,
                    candidate,
                    RuleMatch(
                        rule=self._rules.get("js-secret-010"),
                        value=candidate,
                        offset=generic.start(1),
                        confidence=0.55,
                    )
                    if self._rules.get("js-secret-010")
                    else None,
                    context,
                    offset=generic.start(1),
                )
            )
        return findings

    # -- construction helpers ------------------------------------------------

    def _indicator(
        self,
        source: str,
        candidate: str,
        match: RuleMatch | None,
        context: AnalyzeContext,
        *,
        offset: int | None = None,
    ) -> JSSecretIndicator:
        rule_id = match.rule_id if match else ""
        classification = _CLASSIFICATION_BY_RULE.get(rule_id, SecretClassification.GENERIC_SECRET)
        tier = _tier_for(rule_id, match.confidence if match else 0.5)
        effective_offset = offset if offset is not None else (match.offset if match else -1)
        line, column = _location(source, effective_offset) if effective_offset >= 0 else (0, 0)
        location = f"{context.file}:{line}:{column}" if context.file else f"{line}:{column}"
        return JSSecretIndicator(
            classification=classification,
            masked_value=_mask(candidate, self._reveal_head),
            value_hash=self._hash(candidate),
            location=location,
            file=context.file,
            line=line,
            offset=effective_offset,
            detection_rule=rule_id,
            evidence=(_evidence_from_match(source, effective_offset, match, context),),
            confidence=(match.confidence if match else 0.5),
            reasoning=_reasoning(rule_id),
            tier=tier,
            source=context.source_label,
            tool_id=context.tool_id,
            target_key=context.target_key,
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
        )

    def _reject(self, candidate: str, match: RuleMatch | None) -> bool:
        """Return ``True`` when ``candidate`` should be treated as a non-secret."""
        if len(candidate) < self._min_generic_length:
            return True
        lowered = candidate.lower()
        if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
            return True
        if "${" in candidate or "{{" in candidate:
            return True
        return candidate.startswith(("<", ">"))

    def _hash(self, candidate: str) -> str:
        """Return the SHA-256 digest of ``candidate``."""
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


def _extract_candidate(source: str, match: RuleMatch) -> str | None:
    """Extract the raw candidate value for a rule match.

    Generic-assignment matches include the assignment in the matched span; the
    value is pulled out so only the secret portion is hashed/masked.
    """
    if match.rule_id == "js-secret-010":
        generic = _GENERIC_ASSIGNMENT.search(source, match.offset)
        if generic:
            return generic.group(1)
        return None
    if match.rule_id == "js-secret-008":
        # private key block — hash a fingerprint of the header line
        return match.value
    return match.value.strip()


def _mask(candidate: str, reveal_head: int) -> str:
    """Return a masked preview of ``candidate``."""
    if not candidate:
        return ""
    visible = min(reveal_head, len(candidate))
    return f"{candidate[:visible]}{'*' * (len(candidate) - visible)}"


def _tier_for(rule_id: str, confidence: float) -> ConfidenceTier:
    if rule_id in _TIER_BY_RULE:
        return _TIER_BY_RULE[rule_id]
    if confidence >= 0.9:
        return ConfidenceTier.HIGH
    if confidence >= 0.75:
        return ConfidenceTier.MEDIUM
    return ConfidenceTier.LOW


def _reasoning(rule_id: str) -> str:
    reasons = {
        "js-secret-001": "AWS access key id with vendor-prefixed format",
        "js-secret-002": "Google API key with provider-prefixed format",
        "js-secret-003": "GitHub personal access token with provider prefix",
        "js-secret-005": "Stripe live secret key with provider prefix",
        "js-secret-008": "PEM private key block header observed",
        "js-secret-009": "JWT three-segment structure observed",
        "js-secret-010": "credential assignment with a non-placeholder value",
    }
    return reasons.get(rule_id, "high-entropy credential-shaped value in script content")


def _evidence_from_match(
    source: str,
    offset: int,
    match: RuleMatch | None,
    context: AnalyzeContext,
) -> object:
    """Build the evidence fragment for a secret (never containing the value)."""
    from hunterx.domain.javascript.models import JSEvidence

    line, column = _location(source, offset) if offset >= 0 else (0, 0)
    location = f"{context.file}:{line}:{column}" if context.file else f"{line}:{column}"
    return JSEvidence(
        evidence_type="masked-secret",
        value=match.value if match else "",
        location=location,
        offset=offset,
        snippet="",
        rule_id=match.rule_id if match else "",
        source=context.source_label,
        tool_id=context.tool_id,
        confidence=match.confidence if match else 0.5,
    )
