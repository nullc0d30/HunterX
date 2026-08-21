# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource governance — admission control results.

Every potentially resource-exhausting action (external tool execution, HTTP
probing, model calls, assessment scheduling) passes through the resource
governor before it runs. The governor returns an :class:`Admission` verdict:
``approved`` (run now), ``deferred`` (do not run now; retry later) or ``denied``
(do not run; a resource limit has been reached). Deferred/denied verdicts always
carry a structured reason so the caller can record an honest observation rather
than a silent drop.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Admission:
    """Verdict of a resource-governor admission request.

    Attributes:
        approved: ``True`` when the action may proceed immediately.
        reason: structured machine-readable reason (``""`` when approved).
        delay_s: suggested delay before retrying (``0.0`` when not applicable).

    """

    approved: bool
    reason: str = ""
    delay_s: float = 0.0

    @classmethod
    def allow(cls) -> Admission:
        """Return an approving verdict."""
        return cls(approved=True)

    @classmethod
    def defer(cls, reason: str, *, delay_s: float = 0.0) -> Admission:
        """Return a deferred verdict (retry later under the same call)."""
        return cls(approved=False, reason=reason, delay_s=delay_s)

    @classmethod
    def deny(cls, reason: str) -> Admission:
        """Return a denied verdict (the action must not run)."""
        return cls(approved=False, reason=reason)


__all__ = ["Admission"]
