# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared utility facade (see :mod:`hunterx.shared`)."""

from __future__ import annotations

from hunterx.managers import DependencyManager
from hunterx.shared.di import Container
from hunterx.shared.ids import generate_content_id, generate_id, is_ulid
from hunterx.shared.masking import mask_secret, mask_value
from hunterx.shared.result import Failure, Result, Success
from hunterx.shared.time import utcnow, utcnow_iso

__all__ = [
    "DependencyManager",
    "Container",
    "generate_id",
    "generate_content_id",
    "is_ulid",
    "mask_secret",
    "mask_value",
    "Result",
    "Success",
    "Failure",
    "utcnow",
    "utcnow_iso",
]
