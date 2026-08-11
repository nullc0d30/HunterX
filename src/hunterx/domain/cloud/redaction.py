# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sensitive-data protection for cloud intelligence.

Guarantees that cloud credentials, access keys, secret values, tokens and
private keys never reach observations, evidence or persistence. References are
recorded as fingerprints or masked values only.
"""

from __future__ import annotations

import hashlib
import re

#: Value patterns that are never allowed through as evidence values or details.
_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)(aws_secret_access_key\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(aws_access_key_id\s*[=:]\s*)(\S+)"),
    re.compile(r"(?i)(sk_live_|sk_test_|rk_live_|rk_test_)[0-9A-Za-z]{4,}"),
    re.compile(r"(?i)(pk_live_|pk_test_)[0-9A-Za-z]{4,}"),
    re.compile(r"(?i)://[^:/\s]+:([^@\s/]+)@"),
    re.compile(r"(?i)(xox[baprs]-)[0-9A-Za-z-]{16,}"),
    re.compile(r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[0-9A-Za-z]{20,}"),
    re.compile(r"(?i)(glpat-)[0-9A-Za-z_-]{20,}"),
    re.compile(r"(?i)(AIza)[0-9A-Za-z_-]{20,}"),
    re.compile(r"(?i)(ya29\.)[0-9A-Za-z_-]{20,}"),
    re.compile(r"(?i)(BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)\s+PRIVATE\s+KEY)"),
    re.compile(r"(?i)(-----BEGIN[^-]*PRIVATE KEY-----)"),
    re.compile(r"(?i)(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})"),
    re.compile(r"(?i)(password\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(secret\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(token\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(client[_-]?secret\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(connection[_-]?string\s*[=:]\s*)[^\s]+"),
)

#: Environment-variable names whose values are secrets (never their values).
_SECRET_REFERENCE_NAMES: tuple[str, ...] = (
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SESSION_TOKEN",
    "AZURE_STORAGE_CONNECTION_STRING",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "DATABASE_URL",
    "DB_PASSWORD",
    "POSTGRES_PASSWORD",
    "MYSQL_PASSWORD",
    "REDIS_URL",
    "SECRET_KEY",
    "API_KEY",
    "CLIENT_SECRET",
    "WEBHOOK_SECRET",
    "SIGNING_SECRET",
    "SLACK_SIGNING_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "SUPABASE_SERVICE_ROLE",
    "FIREBASE_ADMIN_SDK",
    "OPENSEARCH_PASSWORD",
)


def contains_secret(value: str) -> bool:
    """Return ``True`` when ``value`` appears to carry a secret value."""
    return any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS)


def sanitize_evidence(value: str, *, max_length: int = 256) -> str:
    """Mask and truncate an evidence value, preserving a safe prefix.

    Any value that matches a secret pattern is fully masked (no plaintext
    fragment survives); other values are truncated to ``max_length``.
    """
    if not value:
        return ""
    if contains_secret(value):
        return _full_mask(value)[:max_length]
    return value[:max_length]


def _full_mask(value: str) -> str:
    """Return a fully masked version of ``value`` (no plaintext fragments)."""
    return "*" * len(value)


def fingerprint(value: str) -> str:
    """Return a stable SHA-256 fingerprint of a reference (never the value)."""
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def secret_reference_kind(value: str) -> str:
    """Return the secret-reference kind for an env-var name (``""`` when unknown)."""
    normalized = value.strip().upper()
    if normalized == "AWS_SECRET_ACCESS_KEY":
        return "aws-access-key"
    if normalized == "AWS_SESSION_TOKEN":
        return "aws-session-token"
    if normalized == "DATABASE_URL" or normalized.endswith("_PASSWORD") or normalized == "DB_PASSWORD":
        return "database-credential"
    if normalized in ("WEBHOOK_SECRET", "SIGNING_SECRET", "SLACK_SIGNING_SECRET"):
        return "webhook-secret"
    if normalized in ("API_KEY", "CLIENT_SECRET", "SECRET_KEY", "STRIPE_SECRET_KEY"):
        return "api-secret"
    return "secret-reference"


def redact_indicators(indicators: tuple[str, ...]) -> tuple[str, ...]:
    """Return indicators with any secret-bearing value redacted."""
    return tuple(sanitize_evidence(str(indicator)) for indicator in indicators)


def safe_context(value: str, *, limit: int = 256) -> str:
    """Return a masked/truncated context snippet for persistence."""
    cleaned = value.replace("\r", " ").replace("\n", " ")
    return sanitize_evidence(cleaned, max_length=limit)
