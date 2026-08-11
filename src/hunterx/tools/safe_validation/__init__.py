# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe validation tool adapters.

Deterministic, in-process safe-probe adapters for the Wave 13 vulnerability
validation engine. Every adapter integrates through the Tool Integration SDK
and only ever emits canonical observations from bounded, already-gated inputs.
"""

from __future__ import annotations

from hunterx.tools.safe_validation.adapters import (
    ErrorBehaviorProbeAdapter,
    PassiveProbeAdapter,
    ValidationToolAdapter,
    VersionProbeAdapter,
    validation_adapters,
)
from hunterx.tools.safe_validation.base import OBSERVATIONS_KEY
from hunterx.tools.safe_validation.registry import (
    VALIDATION_TOOL_IDS,
    ValidationAdapterFactory,
    register_validation_adapters,
)

__all__ = [
    "ErrorBehaviorProbeAdapter",
    "OBSERVATIONS_KEY",
    "PassiveProbeAdapter",
    "VALIDATION_TOOL_IDS",
    "ValidationAdapterFactory",
    "ValidationToolAdapter",
    "VersionProbeAdapter",
    "register_validation_adapters",
    "validation_adapters",
]
