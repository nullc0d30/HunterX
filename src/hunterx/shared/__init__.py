# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared cross-cutting foundation."""

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
