# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Result types.

A lightweight tagged union used instead of ad-hoc ``(ok, value, error)``
tuples. Every public operation that can fail returns a :class:`Result`, which
forces callers to handle both branches explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")
E = TypeVar("E", bound=BaseException)


@dataclass(frozen=True, slots=True)
class Success(Generic[T]):
    """Successful outcome carrying a value."""

    value: T

    @property
    def ok(self) -> bool:
        """Return ``True`` for a success."""
        return True


@dataclass(frozen=True, slots=True)
class Failure(Generic[E]):
    """Failed outcome carrying an exception."""

    error: E

    @property
    def ok(self) -> bool:
        """Return ``False`` for a failure."""
        return False


Result = Success[T] | Failure[E]
"""Union type describing an operation outcome."""


def ok(value: T) -> Success[T]:
    """Construct a :class:`Success` result."""
    return Success(value)


def fail(error: E) -> Failure[E]:
    """Construct a :class:`Failure` result."""
    return Failure(error)
