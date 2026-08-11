# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cache manager facade (see :mod:`hunterx.managers`)."""

from __future__ import annotations

from hunterx.domain.ports.messaging import CachePort
from hunterx.infrastructure.cache import MemoryCache, NullCache
from hunterx.managers import CacheManager

__all__ = ["CacheManager", "CachePort", "MemoryCache", "NullCache"]
