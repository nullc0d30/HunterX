# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target-feedback classification and monitoring.

Phase 2. Classifies each execution outcome into a canonical
:class:`FeedbackSignal` (429, 403, 5xx, timeout, connection failure, latency,
WAF-like behavior, normal) and keeps a bounded rolling window of signals the
adaptive rate controller consumes. Defensive responses are target feedback —
never mission completion.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.adaptive_attack.enums import FeedbackSignal
from hunterx.shared.time import utcnow_iso

#: Error-message markers that indicate a WAF/challenge/block page.
_WAF_MARKERS = ("waf", "challenge", "blocked by", "access denied by security", "cloudflare", "modsecurity", "captcha")

#: Error-message markers that indicate a connection-level failure.
_CONNECTION_MARKERS = ("connection", "reset", "refused", "dns", "resolve", "socket", "network unreachable", "timed out", "timeout")


@dataclass(frozen=True, slots=True)
class FeedbackSample:
    """A single observed target-feedback sample.

    Attributes:
        signal: classified :class:`FeedbackSignal`.
        status_code: HTTP status observed (``None`` when n/a).
        duration_ms: execution/probe latency in milliseconds.
        error: error text (bounded, never raw secrets).
        failure_kind: execution failure-kind string (``""`` when none).
        source: provenance label (``execution``, ``probe``, ``tool``).
        at: UTC ISO-8601 observation stamp.

    """

    signal: FeedbackSignal = FeedbackSignal.NORMAL
    status_code: int | None = None
    duration_ms: int = 0
    error: str = ""
    failure_kind: str = ""
    source: str = "execution"
    at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "signal": self.signal.value,
            "status_code": self.status_code,
            "duration_ms": self.duration_ms,
            "error": self.error[:400],
            "failure_kind": self.failure_kind,
            "source": self.source,
            "at": self.at,
        }


class FeedbackClassifier:
    """Classifies raw execution outcomes into :class:`FeedbackSignal` values.

    Classification is deterministic: HTTP status wins over latency, and the
    explicit error/failure-kind markers resolve ambiguous statuses. A clean
    response is ``NORMAL`` — defensive responses are never treated as evidence.
    """

    def __init__(self, *, high_latency_ms: int = 2000) -> None:
        self.high_latency_ms = max(0, high_latency_ms)

    def classify(
        self,
        *,
        status_code: int | None = None,
        duration_ms: int = 0,
        error: str = "",
        failure_kind: str = "",
        body_hint: str = "",
    ) -> FeedbackSignal:
        """Classify an execution outcome into a :class:`FeedbackSignal`."""
        lowered = f"{error or ''} {failure_kind or ''} {body_hint or ''}".lower()
        for marker in _WAF_MARKERS:
            if marker in lowered:
                return FeedbackSignal.WAF_BLOCKED
        status = int(status_code or 0)
        if status == 429:
            return FeedbackSignal.RATE_LIMITED
        if status == 403:
            return FeedbackSignal.ACCESS_DENIED
        if status >= 500:
            return FeedbackSignal.SERVER_ERROR
        if "timeout" in lowered or "timed out" in lowered:
            return FeedbackSignal.TIMEOUT
        if "connection" in lowered or any(marker in lowered for marker in ("reset", "refused", "dns", "socket")):
            return FeedbackSignal.CONNECTION_FAILURE
        if duration_ms > self.high_latency_ms:
            return FeedbackSignal.HIGH_LATENCY
        return FeedbackSignal.NORMAL

    def to_dict(self) -> dict[str, Any]:
        """Serialize the classifier configuration."""
        return {"high_latency_ms": self.high_latency_ms}


class FeedbackMonitor:
    """Bounded rolling window of target-feedback samples.

    Attributes:
        window_size: maximum number of samples retained.
        samples: most recent samples (oldest first).

    """

    def __init__(
        self,
        *,
        window_size: int = 50,
        classifier: FeedbackClassifier | None = None,
    ) -> None:
        self.window_size = max(1, window_size)
        self.classifier = classifier if classifier is not None else FeedbackClassifier()
        self.samples: deque[FeedbackSample] = deque(maxlen=self.window_size)

    def observe(
        self,
        *,
        status_code: int | None = None,
        duration_ms: int = 0,
        error: str = "",
        failure_kind: str = "",
        body_hint: str = "",
        source: str = "execution",
    ) -> FeedbackSample:
        """Classify and record a feedback sample (returns it)."""
        signal = self.classifier.classify(
            status_code=status_code,
            duration_ms=duration_ms,
            error=error,
            failure_kind=failure_kind,
            body_hint=body_hint,
        )
        sample = FeedbackSample(
            signal=signal,
            status_code=status_code,
            duration_ms=duration_ms,
            error=(error or "")[:800],
            failure_kind=failure_kind,
            source=source,
        )
        self.samples.append(sample)
        return sample

    def signals(self) -> list[FeedbackSample]:
        """Return all retained samples oldest-first."""
        return list(self.samples)

    def recent(self, window: int = 10) -> list[FeedbackSample]:
        """Return the ``window`` most recent samples (oldest-first of those)."""
        return list(self.samples)[-max(1, window) :]

    def last_signal(self) -> FeedbackSignal:
        """Return the most recent classified signal."""
        if not self.samples:
            return FeedbackSignal.NORMAL
        return self.samples[-1].signal

    def defensive_ratio(self, window: int = 10) -> float:
        """Return the share of defensive signals in the recent window."""
        recent = self.recent(window)
        if not recent:
            return 0.0
        defensive = sum(1 for sample in recent if sample.signal.is_defensive)
        return round(defensive / len(recent), 3)

    def healthy_streak(self) -> int:
        """Return the number of trailing consecutive healthy samples."""
        streak = 0
        for sample in reversed(self.samples):
            if sample.signal.is_defensive:
                break
            streak += 1
        return streak

    def defensive_streak(self) -> int:
        """Return the number of trailing consecutive defensive samples."""
        streak = 0
        for sample in reversed(self.samples):
            if not sample.signal.is_defensive:
                break
            streak += 1
        return streak

    def is_healthy(self, window: int = 5) -> bool:
        """Return ``True`` when the recent window carries no defensive signal."""
        return all(not sample.signal.is_defensive for sample in self.recent(window))

    def summary(self) -> dict[str, Any]:
        """Serialize a compact monitor summary."""
        return {
            "window_size": self.window_size,
            "samples": [sample.to_dict() for sample in self.samples],
            "last_signal": self.last_signal().value,
            "defensive_ratio": self.defensive_ratio(),
            "healthy_streak": self.healthy_streak(),
            "defensive_streak": self.defensive_streak(),
        }


__all__ = ["FeedbackClassifier", "FeedbackMonitor", "FeedbackSample"]
