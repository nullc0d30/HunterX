# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Secret discovery tool integrations.

SDK adapters and Tool Intelligence registrations for the secret discovery
tools HunterX integrates (gitleaks). Every adapter runs through the Tool
Integration SDK pipeline and emits canonical redacted secret records.
"""

from __future__ import annotations

from hunterx.tools.secrets.gitleaks import GitleaksAdapter
from hunterx.tools.secrets.registry import (
    SECRETS_TOOL_IDS,
    SecretsAdapterFactory,
    register_secrets_adapters,
    secrets_adapters,
)
from hunterx.tools.secrets.tip import register_secrets_tools, secrets_tool_ids
from hunterx.tools.secrets.trufflehog import TrufflehogAdapter

__all__ = [
    "SECRETS_TOOL_IDS",
    "GitleaksAdapter",
    "SecretsAdapterFactory",
    "TrufflehogAdapter",
    "register_secrets_adapters",
    "register_secrets_tools",
    "secrets_adapters",
    "secrets_tool_ids",
]
