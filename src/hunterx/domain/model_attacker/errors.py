# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI provider failure classification (domain-level contract)."""

from __future__ import annotations

from hunterx.domain.model_attacker.enums import AIFailureCategory


def classify_ai_error(exc: Exception) -> tuple[str, str]:
    """Classify an exception into an AI failure category and provider-labelled message.

    Returns ``(category, message)`` where category is from ``AIFailureCategory``.
    """
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if status is not None:
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = None

    if status == 429:
        return AIFailureCategory.RATE_LIMITED.value, "rate limited (HTTP 429)"
    if status in (401, 403):
        return AIFailureCategory.AUTHENTICATION_ERROR.value, "authentication failed"
    if status == 402:
        return AIFailureCategory.AUTHENTICATION_REQUIRED.value, "payment required"
    if status == 404:
        return AIFailureCategory.MODEL_UNAVAILABLE.value, "model not found"
    if status == 408:
        return AIFailureCategory.TIMEOUT.value, "request timeout"
    if status is not None and status >= 500:
        return AIFailureCategory.PROVIDER_ERROR.value, f"provider error (HTTP {status})"

    # Check exception type/message for more specific classification
    msg = str(exc).lower()
    if "timeout" in msg or "timed out" in msg:
        return AIFailureCategory.TIMEOUT.value, "request timed out"
    if "connection refused" in msg or "connectionrefused" in msg:
        return AIFailureCategory.CONNECTION_REFUSED.value, "connection refused"
    if "connection" in msg or "network" in msg or "unreachable" in msg:
        return AIFailureCategory.CONNECTION_ERROR.value, "network failure"
    if "malformed" in msg or "json" in msg or "decode" in msg:
        return AIFailureCategory.INVALID_RESPONSE.value, "malformed response"

    return AIFailureCategory.UNKNOWN.value, str(exc)
