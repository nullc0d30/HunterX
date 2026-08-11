# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Failure classification and retry policy.

Classifies a failed tool execution into a canonical :class:`FailureClass` and
decides whether the mission may retry it. Only the retryable classes
(transient, rate-limit, timeout, network, tool-crash, parser-failure) are ever
retried; scope, safety, authorization and permanent failures are never retried.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.execution import ExecutionStatus, FailureKind
from hunterx.domain.orchestration.enums import FailureClass, FailureManagement
from hunterx.domain.orchestration.models import RetryPolicy


@dataclass(frozen=True, slots=True)
class FailureReport:
    """A classified failure with its mission-level management decision.

    Attributes:
        failure_class: canonical :class:`FailureClass`.
        management: :class:`FailureManagement` strategy.
        error: error message.
        retryable: whether the failure may be retried.
        retries_performed: retries already performed.

    """

    failure_class: FailureClass = FailureClass.PERMANENT
    management: FailureManagement = FailureManagement.BLOCKED
    error: str = ""
    retryable: bool = False
    retries_performed: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "failure_class": self.failure_class.value,
            "management": self.management.value,
            "error": self.error,
            "retryable": self.retryable,
            "retries_performed": self.retries_performed,
        }


class FailureClassifier:
    """Classifies execution failures into canonical failure classes.

    Mapping is deterministic: ``ExecutionStatus`` and ``FailureKind`` values
    map onto :class:`FailureClass`; anything unrecognised is ``PERMANENT``.
    """

    _STATUS_TO_CLASS: dict[ExecutionStatus, FailureClass] = {
        ExecutionStatus.TIMED_OUT: FailureClass.TIMEOUT,
        ExecutionStatus.FAILED: FailureClass.TRANSIENT,
    }

    _KIND_TO_CLASS: dict[FailureKind, FailureClass] = {
        FailureKind.TIMEOUT: FailureClass.TIMEOUT,
        FailureKind.RESOURCE_EXHAUSTED: FailureClass.TRANSIENT,
        FailureKind.CONFIGURATION: FailureClass.INVALID_INPUT,
        FailureKind.INSTALLATION: FailureClass.TOOL_CRASH,
        FailureKind.OUTPUT_INVALID: FailureClass.PARSER_FAILURE,
        FailureKind.NORMALIZATION_FAILED: FailureClass.PARSER_FAILURE,
        FailureKind.SANDBOX_VIOLATION: FailureClass.SAFETY_FAILURE,
        FailureKind.MISSING_DEPENDENCY: FailureClass.TRANSIENT,
    }

    def classify(self, *, status: ExecutionStatus | str | None = None, failure_kind: FailureKind | str | None = None) -> FailureClass:
        """Classify an execution outcome into a :class:`FailureClass`."""
        if isinstance(status, ExecutionStatus) and status in self._STATUS_TO_CLASS:
            return self._STATUS_TO_CLASS[status]
        if isinstance(status, str):
            try:
                status_enum = ExecutionStatus(status)
                if status_enum in self._STATUS_TO_CLASS:
                    return self._STATUS_TO_CLASS[status_enum]
            except ValueError:
                pass
        if isinstance(failure_kind, FailureKind) and failure_kind in self._KIND_TO_CLASS:
            return self._KIND_TO_CLASS[failure_kind]
        if isinstance(failure_kind, str):
            try:
                kind_enum = FailureKind(failure_kind)
                if kind_enum in self._KIND_TO_CLASS:
                    return self._KIND_TO_CLASS[kind_enum]
            except ValueError:
                pass
        return FailureClass.PERMANENT

    def classify_message(self, error: str) -> FailureClass:
        """Classify a failure from its error message (heuristic)."""
        lowered = (error or "").lower()
        if any(token in lowered for token in ("429", "rate limit", "rate_limit", "too many requests")):
            return FailureClass.RATE_LIMIT
        if any(token in lowered for token in ("timed out", "timeout", "timedout")):
            return FailureClass.TIMEOUT
        if any(token in lowered for token in ("dns", "connection", "socket", "network", "resolve")):
            return FailureClass.NETWORK
        if any(token in lowered for token in ("parse", "parser", "json", "invalid output")):
            return FailureClass.PARSER_FAILURE
        if any(token in lowered for token in ("scope", "out of scope", "out-of-scope")):
            return FailureClass.SCOPE_FAILURE
        if any(token in lowered for token in ("safety", "forbidden", "unsafe")):
            return FailureClass.SAFETY_FAILURE
        if any(token in lowered for token in ("crash", "segfault", "killed", "exit code")):
            return FailureClass.TOOL_CRASH
        return FailureClass.PERMANENT


class RetryEngine:
    """Decides whether and how to retry a failed task.

    Only retryable failure classes are retried, up to ``RetryPolicy.max_attempts``.
    Never retry: scope failure, safety failure, authorization failure and
    destructive-behavior failures.
    """

    def __init__(
        self,
        classifier: FailureClassifier | None = None,
        policy: RetryPolicy | None = None,
    ) -> None:
        self._classifier = classifier or FailureClassifier()
        self._policy = policy or RetryPolicy()

    def report(
        self,
        *,
        status: ExecutionStatus | str | None = None,
        failure_kind: FailureKind | str | None = None,
        error: str = "",
        retries_performed: int = 0,
    ) -> FailureReport:
        """Build a failure report for an execution outcome."""
        failure_class = self._classifier.classify(status=status, failure_kind=failure_kind)
        if failure_class is FailureClass.PERMANENT and error:
            message_class = self._classifier.classify_message(error)
            if message_class is not FailureClass.PERMANENT:
                failure_class = message_class

        retryable = failure_class.retryable and retries_performed < self._policy.retries()
        management = self._management(failure_class, retryable)
        return FailureReport(
            failure_class=failure_class,
            management=management,
            error=error,
            retryable=retryable,
            retries_performed=retries_performed,
        )

    def should_retry(self, report: FailureReport) -> bool:
        """Return ``True`` when ``report`` may be retried."""
        return report.retryable and report.failure_class.retryable

    def delay_seconds(self, attempt: int) -> float:
        """Return the backoff delay for a retry ``attempt`` (0-based)."""
        policy = self._policy
        delay = min(policy.base_delay_s * (policy.backoff_factor**attempt), policy.max_delay_s)
        if policy.jitter:
            import random  # nosec B311 - jitter is non-security randomness

            delay = delay * (0.5 + random.random() * 0.5)
        return round(max(0.0, delay), 3)

    @staticmethod
    def _management(failure_class: FailureClass, retryable: bool) -> FailureManagement:
        if failure_class in (FailureClass.SCOPE_FAILURE, FailureClass.SAFETY_FAILURE):
            return FailureManagement.BLOCKED
        if failure_class is FailureClass.AUTHORIZATION_FAILURE:
            return FailureManagement.BLOCKED
        if failure_class is FailureClass.PERMANENT:
            return FailureManagement.CRITICAL
        if retryable:
            return FailureManagement.RECOVERABLE
        return FailureManagement.DEFERRED
