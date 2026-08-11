# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Configuration manager.

Loads, validates and merges configuration from environment variables, default
values and optional profile files (``hunterx.yaml``). The manager exposes
typed settings to every layer.
"""

from __future__ import annotations

from hunterx.config.loader import ConfigurationManager, load_default_settings
from hunterx.config.settings import (
    ApiSettings,
    CacheSettings,
    DatabaseSettings,
    QueueSettings,
    Settings,
)

__all__ = [
    "Settings",
    "DatabaseSettings",
    "CacheSettings",
    "QueueSettings",
    "ApiSettings",
    "ConfigurationManager",
    "load_default_settings",
]
