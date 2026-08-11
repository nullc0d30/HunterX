# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication observation validation.

Deterministic structural and semantic validation of authentication
observations: every record must carry a resolvable origin (or asset), a valid
confidence within ``[0, 1]`` and, for typed records, a known kind. Invalid
records are flagged with a machine-readable issue so downstream stages can drop
or repair them without ever trusting malformed input.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

#: Confidence bounds applied to every observation.
_MIN_CONFIDENCE = 0.0
_MAX_CONFIDENCE = 1.0


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A single validation finding for an observation.

    Attributes:
        code: stable machine-readable issue code.
        message: human-readable description.
        field: the field the issue concerns.

    """

    code: str
    message: str
    field: str = ""


@dataclass(frozen=True, slots=True)
class AuthValidationResult:
    """The outcome of validating one observation.

    Attributes:
        observation: the validated observation.
        valid: whether the observation is valid.
        issues: the validation issues found.

    """

    observation: Any
    valid: bool
    issues: tuple[ValidationIssue, ...] = ()


class AuthValidator:
    """Validate authentication observations before persistence.

    Usage::

        validator = AuthValidator()
        result = validator.validate(observation)
    """

    def validate(self, observation: Any) -> AuthValidationResult:
        """Validate a single observation and return the result."""
        issues: list[ValidationIssue] = []
        origin = str(getattr(observation, "origin", "") or "")
        if not origin:
            issues.append(ValidationIssue("missing-origin", "origin must not be empty", "origin"))
        confidence = _confidence(observation)
        if not (_MIN_CONFIDENCE <= confidence <= _MAX_CONFIDENCE):
            issues.append(ValidationIssue("bad-confidence", "confidence must be within [0, 1]", "confidence"))
        return AuthValidationResult(
            observation=observation,
            valid=not issues,
            issues=tuple(issues),
        )

    def validate_many(self, observations: Iterable[Any]) -> list[AuthValidationResult]:
        """Validate many observations, preserving order."""
        return [self.validate(observation) for observation in observations]

    def filter_valid(self, observations: Iterable[Any]) -> list[Any]:
        """Return the observations that pass validation."""
        return [result.observation for result in self.validate_many(observations) if result.valid]


def _confidence(observation: Any) -> float:
    try:
        return float(getattr(observation, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0
