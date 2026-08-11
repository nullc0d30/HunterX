# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Baseline & differential testing engine.

Sprint 032. Maintains baseline behavior for HTTP, DNS, TLS, authentication,
response codes, headers, content, timing, parameters and application behavior.
Differential tests compare a test request against a matching baseline and
classify the behavior delta (status change, length change, header change,
reflection, timing, callback, error behavior, content mutation). This is the
behavioral evidence that separates a real weakness from a false positive.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.mission_orchestration.enums import DifferentialSignal
from hunterx.domain.mission_orchestration.models import (
    BaselineObservation,
    DifferentialResult,
)
from hunterx.shared.ids import generate_content_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class TestResponse:
    """A response under test for differential comparison.

    ``__test__ = False`` keeps pytest from treating this dataclass as a test
    collection target.
    """

    __test__ = False

    status_code: int = 0
    headers: dict[str, str] = None  # type: ignore[assignment]
    content_length: int = 0
    body: str = ""
    timing_ms: int = 0
    parameters: dict[str, Any] = None  # type: ignore[assignment]
    raw: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers or {}))
        object.__setattr__(self, "parameters", dict(self.parameters or {}))
        object.__setattr__(self, "raw", dict(self.raw or {}))


class BaselineEngine:
    """Record, retrieve and match baseline observations."""

    def __init__(self) -> None:
        self._baselines: list[BaselineObservation] = []

    def capture(
        self,
        *,
        mission_id: str,
        asset_key: str,
        request_fingerprint: str = "",
        status_code: int = 0,
        headers: Mapping[str, str] | None = None,
        content_length: int = 0,
        body: str = "",
        timing_ms: int = 0,
        parameters: Mapping[str, Any] | None = None,
        provenance: Mapping[str, Any] | None = None,
    ) -> BaselineObservation:
        """Record a baseline observation."""
        baseline = BaselineObservation(
            baseline_id=generate_content_id(mission_id, asset_key, request_fingerprint or utcnow_iso()),
            mission_id=mission_id,
            asset_key=asset_key,
            request_fingerprint=request_fingerprint,
            status_code=status_code,
            headers=dict(headers or {}),
            content_length=content_length,
            body_hash=_hash_body(body),
            timing_ms=timing_ms,
            parameters=dict(parameters or {}),
            provenance=dict(provenance or {}),
        )
        self._baselines.append(baseline)
        return baseline

    def snapshot(self) -> list[BaselineObservation]:
        """Return the recorded baselines."""
        return list(self._baselines)

    def match(
        self,
        *,
        asset_key: str,
        request_fingerprint: str = "",
        status_code: int | None = None,
    ) -> BaselineObservation | None:
        """Return the closest baseline for the given request context."""
        candidates = [b for b in self._baselines if b.asset_key == asset_key]
        if not candidates:
            return None
        if request_fingerprint:
            for baseline in candidates:
                if baseline.request_fingerprint == request_fingerprint:
                    return baseline
        if status_code is not None:
            for baseline in candidates:
                if baseline.status_code == status_code:
                    return baseline
        return candidates[-1]

    def reset(self) -> None:
        """Drop all baselines (test isolation)."""
        self._baselines.clear()


class DifferentialTestEngine:
    """Compare a test request against a baseline and classify the delta.

    Differential classification is deterministic: the signals are computed from
    the raw response comparison and the final classification aggregates them.
    """

    #: Status codes that always indicate a behavioral delta when changed.
    _SIGNALING_STATUS = {200, 201, 204, 301, 302, 400, 401, 403, 404, 500, 502}

    def compare(
        self,
        *,
        mission_id: str,
        asset_key: str,
        baseline: BaselineObservation,
        test: TestResponse,
        classification_hint: str = "",
    ) -> DifferentialResult:
        """Compare ``test`` against ``baseline`` and classify the delta."""
        signals: list[DifferentialSignal] = []

        if test.status_code != baseline.status_code:
            signals.append(DifferentialSignal.STATUS_CHANGE)

        if _length_delta(test.content_length, baseline.content_length) > 0.05:
            signals.append(DifferentialSignal.LENGTH_CHANGE)

        if _header_delta(test.headers, baseline.headers):
            signals.append(DifferentialSignal.HEADER_CHANGE)

        if _reflects(test.body):
            signals.append(DifferentialSignal.REFLECTION)

        if test.timing_ms > 0 and baseline.timing_ms > 0 and test.timing_ms >= baseline.timing_ms * 3:
            signals.append(DifferentialSignal.TIMING_DELTA)

        callback = _callback_detected(test.raw)
        if callback:
            signals.append(DifferentialSignal.CALLBACK)

        if _error_behavior(test.body):
            signals.append(DifferentialSignal.ERROR_BEHAVIOR)

        if not signals:
            signals.append(DifferentialSignal.NO_DELTA)

        classification = _classify(signals, classification_hint)
        return DifferentialResult(
            result_id=generate_content_id(mission_id, asset_key, str(test.status_code), str(test.content_length)),
            mission_id=mission_id,
            asset_key=asset_key,
            baseline_id=baseline.baseline_id,
            signals=tuple(signals),
            delta_summary={
                "status_from": baseline.status_code,
                "status_to": test.status_code,
                "length_from": baseline.content_length,
                "length_to": test.content_length,
                "timing_from_ms": baseline.timing_ms,
                "timing_to_ms": test.timing_ms,
            },
            matched_baseline=DifferentialSignal.NO_DELTA not in signals,
            evidence_classification=classification,
        )


def _hash_body(body: str) -> str:
    """Return a stable content hash for a response body."""
    return generate_content_id("baseline-body", body)[:16]


def _length_delta(actual: int, baseline: int) -> float:
    """Return the relative length delta in ``[0, inf)``."""
    if baseline <= 0:
        return 1.0 if actual > 0 else 0.0
    return abs(actual - baseline) / baseline


def _header_delta(actual: Mapping[str, str], baseline: Mapping[str, str]) -> bool:
    """Return ``True`` when security-relevant headers changed."""
    sensitive = {"server", "x-powered-by", "set-cookie", "content-type", "location", "www-authenticate"}
    return any(header.lower() in sensitive and baseline.get(header) != value for header, value in actual.items())


def _reflects(body: str) -> bool:
    """Return ``True`` when the body contains reflection markers."""
    markers = ("hunterxprobe", "qwertyuiop", "<script", "---reflection---")
    lowered = body.lower()
    return any(marker in lowered for marker in markers)


def _callback_detected(raw: Mapping[str, Any] | None) -> bool:
    """Return ``True`` when the response records a controlled callback."""
    if not raw:
        return False
    return bool(raw.get("callback") or raw.get("oob") or raw.get("interactsh_id"))


def _error_behavior(body: str) -> bool:
    """Return ``True`` when the body shows database/parser error behavior."""
    markers = (
        "sql syntax",
        "mysql_fetch",
        "you have an error in your sql",
        "sqlite3.operationalerror",
        "unterminated string",
        "traceback",
        "syntaxerror",
        "ora-",
        "pg_",
    )
    lowered = body.lower()
    return any(marker in lowered for marker in markers)


def _classify(signals: Sequence[DifferentialSignal], hint: str) -> str:
    """Return the evidence classification of a differential result."""
    if DifferentialSignal.CALLBACK in signals:
        return "callback_confirmed"
    if hint and hint == "sql_injection" and (
        DifferentialSignal.ERROR_BEHAVIOR in signals or DifferentialSignal.TIMING_DELTA in signals
    ):
        return "sql_injection_indicative"
    if DifferentialSignal.REFLECTION in signals and DifferentialSignal.STATUS_CHANGE not in signals:
        return "reflection_indicative"
    if DifferentialSignal.NO_DELTA in signals:
        return "no_behavioral_delta"
    return "behavioral_delta"


__all__ = [
    "BaselineEngine",
    "BaselineObservation",
    "DifferentialSignal",
    "DifferentialTestEngine",
    "TestResponse",
]
