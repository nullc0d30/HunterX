# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Retry manager.

Decides whether a failed execution may be retried and computes backoff delays.
Retries are only permitted for failure kinds declared retryable by the
execution's retry policy, up to ``max_attempts`` total attempts.
"""

from __future__ import annotations

import random

from hunterx.domain.execution import FailureKind, RetryPolicy


class RetryManager:
    """Evaluate retry eligibility and compute backoff delays.

    Usage::

        manager = RetryManager()
        manager.eligible(policy, kind, attempt=1)   # True/False
        delay = manager.delay_for(policy, attempt=1)
    """

    def eligible(self, policy: RetryPolicy, kind: FailureKind | None, attempt: int) -> bool:
        """Return ``True`` when a retry is permitted.

        ``attempt`` is the number of attempts already made (0-based). A retry
        is allowed when the attempt count is below the retry budget and the
        failure kind is listed in the policy's retryable kinds.
        """
        if kind is None:
            return False
        if kind not in policy.retryable_kinds:
            return False
        return attempt < policy.retries()

    def delay_for(self, policy: RetryPolicy, attempt: int) -> float:
        """Return the backoff delay in seconds before ``attempt`` (0-based).

        Delay is ``base * factor^attempt`` capped at ``max_delay_s``, with
        optional jitter of up to 20%.
        """
        delay = policy.base_delay_s * (policy.backoff_factor**attempt)
        delay = min(delay, policy.max_delay_s)
        if policy.jitter:
            delay *= random.uniform(0.8, 1.2)  # nosec B311  # non-cryptographic jitter
        return max(0.0, delay)
