# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology observation validation.

Deterministic structural and semantic validation of technology observations:
every record must carry a non-empty asset, a resolvable name, a valid category
and a confidence within ``[0, 1]``. Invalid records are flagged with a
machine-readable issue so downstream stages can drop or repair them without
ever trusting malformed input.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from hunterx.domain.technology.models import TechnologyObservation

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
class TechnologyValidationResult:
    """The outcome of validating one observation.

    Attributes:
        observation: the validated observation.
        valid: whether the observation is valid.
        issues: the validation issues found.
        status: the normalized validation status (``valid``/``unknown``/``invalid``).

    """

    observation: TechnologyObservation
    valid: bool
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def status(self) -> str:
        """Return the canonical validation status."""
        if self.valid:
            return "valid"
        if any(issue.code == "missing-name" for issue in self.issues):
            return "invalid"
        return "unknown"


class TechnologyValidator:
    """Validate technology observations before persistence.

    Usage::

        validator = TechnologyValidator()
        result = validator.validate(observation)
    """

    def validate(self, observation: TechnologyObservation) -> TechnologyValidationResult:
        """Validate a single observation and return the result."""
        issues: list[ValidationIssue] = []
        if not observation.asset.strip():
            issues.append(ValidationIssue("missing-asset", "asset must not be empty", "asset"))
        name = (observation.canonical_name or observation.raw_name).strip()
        if not name:
            issues.append(ValidationIssue("missing-name", "technology name must not be empty", "canonical_name"))
        if not (0.0 <= float(observation.confidence) <= 1.0):
            issues.append(ValidationIssue("bad-confidence", "confidence must be within [0, 1]", "confidence"))
        if observation.version and not _looks_like_version(observation.version):
            issues.append(ValidationIssue("bad-version", "version value looks malformed", "version"))
        return TechnologyValidationResult(
            observation=observation,
            valid=not issues,
            issues=tuple(issues),
        )

    def validate_many(self, observations: Iterable[TechnologyObservation]) -> list[TechnologyValidationResult]:
        """Validate many observations, preserving order."""
        return [self.validate(observation) for observation in observations]

    def filter_valid(self, observations: Iterable[TechnologyObservation]) -> list[TechnologyObservation]:
        """Return the observations that pass validation, with status applied."""
        results = self.validate_many(observations)
        valid: list[TechnologyObservation] = []
        for result in results:
            status = result.status
            observation = result.observation
            from dataclasses import replace

            if observation.validation_status != status:
                observation = replace(observation, validation_status=status)
            if result.valid:
                valid.append(observation)
        return valid

    def valid_status(self, observation: TechnologyObservation) -> str:
        """Return the validation status string for ``observation``."""
        return self.validate(observation).status


def _looks_like_version(value: str) -> bool:
    """Return whether ``value`` plausibly parses as a version token."""
    import re

    return bool(re.search(r"\d", value))
