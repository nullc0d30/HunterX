# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Identity and content-hash utilities.

IDs follow the ULID specification so they are time-sortable, collision-safe,
and lexicographically ordered. Content hashes use SHA-256 and are used to
deduplicate findings, evidence, and knowledge records.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

_BYTES_PER_MS = 10**7
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ULID_BASE = len(_ULID_ALPHABET)


def _encode_base32(number: int, length: int) -> str:
    """Encode ``number`` in Crockford base-32 padded to ``length`` chars."""
    if number == 0:
        return _ULID_ALPHABET[0] * length
    encoded: list[str] = []
    while number > 0:
        number, remainder = divmod(number, _ULID_BASE)
        encoded.append(_ULID_ALPHABET[remainder])
    return "".join(reversed(encoded)).rjust(length, _ULID_ALPHABET[0])


def generate_id() -> str:
    """Generate a time-ordered ULID-style identifier (26 characters).

    The identifier embeds the millisecond timestamp in its most significant
    bits, making consecutive IDs sortable by creation time without a separate
    timestamp column.
    """
    timestamp_ms = int(time.time() * 1000)
    random_bits = int.from_bytes(os.urandom(10), "big")
    return _encode_base32(timestamp_ms & ((1 << 48) - 1), 10) + _encode_base32(
        random_bits, 16
    )


def is_ulid(value: str) -> bool:
    """Return ``True`` if ``value`` is a valid ULID-format identifier."""
    if len(value) != 26:
        return False
    return all(char in _ULID_ALPHABET for char in value)


def generate_content_id(*parts: Any) -> str:
    """Generate a stable SHA-256 content hash for a set of value parts.

    The same input parts always yield the same hash, which makes it safe to
    use as a deduplication key across findings, evidence, and knowledge
    records. ``None`` values and ``False`` are treated as ``"nil"`` so the
    hash is stable regardless of optional-field presence.
    """
    hasher = hashlib.sha256()
    for part in parts:
        if part is None or part is False:
            hasher.update(b"nil")
            continue
        if isinstance(part, bytes):
            hasher.update(part)
        else:
            hasher.update(str(part).encode("utf-8"))
        hasher.update(b"\x1f")
    return hasher.hexdigest()
