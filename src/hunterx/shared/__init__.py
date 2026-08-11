# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared cross-cutting foundation.

This package holds the low-level building blocks used by every layer of the
platform: identity generation (ULIDs), content hashing, time handling, secret
masking, result types, and the dependency-injection container.

The contents of this package MUST be pure Python (standard library only) so
that every other layer can depend on it without side effects.
"""

from __future__ import annotations

from hunterx.shared.ids import (
    generate_content_id,
    generate_id,
    is_ulid,
)
from hunterx.shared.masking import MaskConfig, mask_secret, mask_value
from hunterx.shared.result import Failure, Result, Success

__all__ = [
    "generate_id",
    "generate_content_id",
    "is_ulid",
    "mask_value",
    "mask_secret",
    "MaskConfig",
    "Result",
    "Success",
    "Failure",
]
