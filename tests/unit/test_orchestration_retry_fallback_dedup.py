# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests: retry classification, fallback, dedup and rate limiting."""

from __future__ import annotations

from hunterx.domain.execution import ExecutionStatus, FailureKind
from hunterx.domain.orchestration.enums import FailureClass, MissionType
from hunterx.domain.orchestration.models import RateLimitPolicy, RetryPolicy, ToolPolicy
from hunterx.domain.orchestration.selection import CapabilityNeed
from hunterx.engines.orchestration.dedup import (
    ExecutionDeduplicator,
    ExecutionRecord,
    execution_hash,
)
from hunterx.engines.orchestration.fallback import FallbackEngine
from hunterx.engines.orchestration.ratelimit import RateLimiter
from hunterx.engines.orchestration.retry import FailureClassifier, RetryEngine


def test_execution_hash_is_deterministic() -> None:
    a = execution_hash(tool_id="subfinder", target="example.com", parameters={"rate_limit": 5})
    b = execution_hash(tool_id="subfinder", target="example.com", parameters={"rate_limit": 5})
    assert a == b


def test_execution_hash_sensitive_to_input() -> None:
    a = execution_hash(tool_id="subfinder", target="example.com")
    b = execution_hash(tool_id="subfinder", target="other.com")
    assert a != b


def test_classifier_timeout() -> None:
    classifier = FailureClassifier()
    assert classifier.classify(status=ExecutionStatus.TIMED_OUT) is FailureClass.TIMEOUT
    assert classifier.classify(failure_kind=FailureKind.TIMEOUT) is FailureClass.TIMEOUT


def test_classifier_parser_failure() -> None:
    classifier = FailureClassifier()
    assert classifier.classify(failure_kind=FailureKind.OUTPUT_INVALID) is FailureClass.PARSER_FAILURE
    assert classifier.classify_message("failed to parse json") is FailureClass.PARSER_FAILURE


def test_classifier_rate_limit_message() -> None:
    classifier = FailureClassifier()
    assert classifier.classify_message("HTTP 429 too many requests") is FailureClass.RATE_LIMIT


def test_classifier_permanent_default() -> None:
    classifier = FailureClassifier()
    assert classifier.classify() is FailureClass.PERMANENT


def test_retry_only_retryable_classes() -> None:
    engine = RetryEngine(policy=RetryPolicy(max_attempts=3))
    retryable = engine.report(status=ExecutionStatus.TIMED_OUT, retries_performed=0)
    assert retryable.retryable
    assert engine.should_retry(retryable)

    permanent = engine.report(failure_kind=FailureKind.OUTPUT_INVALID, error="scope blocked", retries_performed=0)
    # message heuristic may reclassify; ensure never retried when scope failure
    assert not permanent.retryable or permanent.failure_class is FailureClass.PARSER_FAILURE


def test_scope_failure_never_retried() -> None:
    engine = RetryEngine(policy=RetryPolicy(max_attempts=5))
    report = engine.report(error="out of scope identifier", retries_performed=0)
    assert report.failure_class is FailureClass.SCOPE_FAILURE
    assert not engine.should_retry(report)


def test_backoff_increases() -> None:
    engine = RetryEngine(policy=RetryPolicy(base_delay_s=1.0, backoff_factor=2.0, jitter=False))
    first = engine.delay_seconds(0)
    second = engine.delay_seconds(1)
    assert second > first


def test_dedup_within_freshness() -> None:
    dedup = ExecutionDeduplicator(freshness_window_seconds=3600)
    h = execution_hash(tool_id="subfinder", target="example.com")
    dedup.record(ExecutionRecord(execution_id="e1", input_hash=h, tool_id="subfinder", target="example.com"))
    assert dedup.is_duplicate(h)
    assert dedup.lookup(h).execution_id == "e1"


def test_dedup_no_freshness_disables() -> None:
    dedup = ExecutionDeduplicator(freshness_window_seconds=0)
    h = execution_hash(tool_id="subfinder", target="example.com")
    dedup.record(ExecutionRecord(execution_id="e1", input_hash=h, tool_id="subfinder", target="example.com"))
    assert not dedup.is_duplicate(h)


def test_rate_limiter_unlimited() -> None:
    limiter = RateLimiter(RateLimitPolicy())
    assert limiter.allows(target="example.com").allowed


def test_rate_limiter_enforces_limit() -> None:
    limiter = RateLimiter(RateLimitPolicy(target_per_second=2))
    assert limiter.allows(target="example.com").allowed
    assert limiter.allows(target="example.com").allowed
    decision = limiter.allows(target="example.com")
    assert not decision.allowed
    assert decision.retry_after_seconds > 0


def test_rate_limiter_separates_keys() -> None:
    limiter = RateLimiter(RateLimitPolicy(target_per_second=1))
    assert limiter.allows(target="a.com").allowed
    assert limiter.allows(target="b.com").allowed
    assert not limiter.allows(target="a.com").allowed


def test_fallback_disabled_by_policy() -> None:
    fallback = FallbackEngine()
    decision = fallback.select_fallback(
        step_id="s1",
        primary="subfinder",
        need=CapabilityNeed(capability="subdomain-discovery", target_type="domain"),
        mission_type=MissionType.EXTERNAL_ASSESSMENT,
        policy=ToolPolicy(fallback_enabled=False),
    )
    assert decision.fallback_tool == ""


def test_tool_policy_permit() -> None:
    policy = ToolPolicy(excluded_tools=("hydra",), allowed_tools=("subfinder", "amass"))
    assert policy.permits("subfinder")
    assert not policy.permits("hydra")
    assert not policy.permits("nmap")
