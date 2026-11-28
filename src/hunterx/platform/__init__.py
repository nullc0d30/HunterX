# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Platform composition root."""

from __future__ import annotations

from hunterx.platform.assembler import build_platform
from hunterx.platform.platform import Platform

__all__ = [
    "Platform",
    "build_platform",
]
