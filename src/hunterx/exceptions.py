# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Convenience re-export of the full exception hierarchy."""

from __future__ import annotations

from hunterx.domain.exceptions import *  # noqa: F403
from hunterx.domain.exceptions import HunterXError, HunterXErrorCode

__all__ = ["HunterXError", "HunterXErrorCode"]
