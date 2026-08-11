# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Time handling helpers.

All timestamps crossing the platform boundary are UTC ISO-8601 strings or
UTC-aware ``datetime`` objects. This module centralizes that contract so no
layer can accidentally introduce naive/local time handling.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware ``datetime``."""
    return datetime.now(UTC)


def utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return utcnow().isoformat()


def to_utc_iso(value: datetime | None = None) -> str:
    """Normalize a datetime (or now) to an ISO-8601 UTC string."""
    if value is None:
        value = utcnow()
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def to_utc_datetime(value: str | datetime | None = None) -> datetime:
    """Parse an ISO-8601 string into a UTC-aware ``datetime``."""
    if value is None:
        return utcnow()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def unix_epoch_ms(dt: datetime | None = None) -> int:
    """Return milliseconds since the Unix epoch for ``dt`` (default: now)."""
    return int(to_utc_datetime(dt).timestamp() * 1000)


def monotonic_ms() -> int:
    """Return a monotonic clock value in milliseconds (for elapsed-time math)."""
    return int(time.monotonic() * 1000)
