# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Severity and risk scoring value objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from hunterx.domain.exceptions import InvalidFindingError


class Severity(IntEnum):
    """Canonical severity levels, ordered by increasing impact."""

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse a severity from a string (case-insensitive)."""
        try:
            return cls[value.upper()]
        except KeyError:
            raise InvalidFindingError(f"Unknown severity '{value}'.") from None


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A 0..10 numeric risk score with its derived severity.

    Attributes:
        score: normalized risk value in ``[0, 10]``.

    """

    score: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 10.0:
            raise InvalidFindingError(f"Risk score must be in [0, 10], got {self.score!r}.")

    @property
    def severity(self) -> Severity:
        """Derive a severity band from the numeric score."""
        if self.score >= 9.0:
            return Severity.CRITICAL
        if self.score >= 7.0:
            return Severity.HIGH
        if self.score >= 4.0:
            return Severity.MEDIUM
        if self.score > 0.0:
            return Severity.LOW
        return Severity.NONE
