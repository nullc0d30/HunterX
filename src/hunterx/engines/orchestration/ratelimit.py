# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Rate limiting for mission tasks.

A token-bucket rate limiter keyed by scope level (global, mission, target,
domain, ip, tool). Limits are configured by the mission :class:`RateLimitPolicy`;
a limit of ``0`` means unlimited. The limiter refuses tasks that exceed a limit
so the mission never hammers a target or a service.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from hunterx.domain.orchestration.models import RateLimitPolicy


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """A rate-limit decision.

    Attributes:
        allowed: whether the task may proceed.
        key: the limit key that was evaluated.
        reason: human-readable justification.
        retry_after_seconds: how long to wait before retrying (``0`` when
            unlimited or allowed).

    """

    allowed: bool
    key: str = ""
    reason: str = "allowed"
    retry_after_seconds: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "allowed": self.allowed,
            "key": self.key,
            "reason": self.reason,
            "retry_after_seconds": self.retry_after_seconds,
        }


class _Bucket:
    """A per-key token bucket."""

    __slots__ = ("capacity", "tokens", "refill", "updated")

    def __init__(self, capacity: float) -> None:
        self.capacity = capacity
        self.tokens = capacity
        self.refill = capacity
        self.updated = time.monotonic()


class RateLimiter:
    """Token-bucket rate limiter for mission tasks.

    Keys are derived from the policy dimensions. A task is allowed only when
    every applicable key has a token available; the smallest remaining budget
    determines ``retry_after_seconds``.
    """

    def __init__(self, policy: RateLimitPolicy | None = None) -> None:
        self._policy = policy or RateLimitPolicy()
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allows(
        self,
        *,
        mission_id: str = "",
        target: str = "",
        domain: str = "",
        ip: str = "",
        tool_id: str = "",
    ) -> RateLimitDecision:
        """Return a rate-limit decision for a task.

        Args:
            mission_id: owning mission (mission-level limit).
            target: target identifier (target-level limit).
            domain: registrable domain (domain-level limit).
            ip: IP address (ip-level limit).
            tool_id: tool id (tool-level limit).

        """
        policy = self._policy
        keys: list[tuple[str, float]] = []
        if policy.global_per_second > 0:
            keys.append(("global", policy.global_per_second))
        if policy.mission_per_second > 0 and mission_id:
            keys.append((f"mission:{mission_id}", policy.mission_per_second))
        if policy.target_per_second > 0 and target:
            keys.append((f"target:{target}", policy.target_per_second))
        if policy.domain_per_second > 0 and domain:
            keys.append((f"domain:{domain}", policy.domain_per_second))
        if policy.ip_per_second > 0 and ip:
            keys.append((f"ip:{ip}", policy.ip_per_second))
        if policy.tool_per_second > 0 and tool_id:
            keys.append((f"tool:{tool_id}", policy.tool_per_second))
        if not keys:
            return RateLimitDecision(allowed=True)

        max_wait = 0.0
        with self._lock:
            now = time.monotonic()
            for key, capacity in keys:
                bucket = self._buckets.get(key)
                if bucket is None:
                    bucket = _Bucket(capacity)
                    bucket.updated = now
                    self._buckets[key] = bucket
                bucket.tokens = min(bucket.capacity, bucket.tokens + (now - bucket.updated) * bucket.refill)
                bucket.updated = now
                if bucket.tokens < 1.0:
                    wait = (1.0 - bucket.tokens) / bucket.refill
                    max_wait = max(max_wait, wait)
                else:
                    bucket.tokens -= 1.0
        if max_wait > 0:
            return RateLimitDecision(
                allowed=False,
                key=",".join(key for key, _ in keys),
                reason=f"rate limit exceeded for {len(keys)} key(s)",
                retry_after_seconds=round(max_wait, 3),
            )
        return RateLimitDecision(allowed=True, key=",".join(key for key, _ in keys))

    def reset(self) -> None:
        """Reset every bucket."""
        with self._lock:
            self._buckets.clear()


def normalize_domain(target: str) -> str:
    """Extract a registrable-ish domain label for rate-limit keys."""
    import ipaddress

    value = target.strip()
    if "://" in value:
        from urllib.parse import urlparse

        value = urlparse(value).netloc or value
    value = value.split("/", 1)[0].split(":", 1)[0].strip("[]")
    try:
        ipaddress.ip_address(value)
        return ""
    except ValueError:
        labels = value.split(".")
        if len(labels) >= 2:
            return ".".join(labels[-2:])
        return value
