# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Value objects.

Value objects are immutable, interchangeable domain primitives identified by
their value rather than their identity.
"""

from __future__ import annotations

from hunterx.domain.value_objects.scope import (
    URL,
    AssetIdentifier,
    DomainName,
    Hostname,
    IPAddress,
    Port,
    Protocol,
    Scope,
    Service,
)
from hunterx.domain.value_objects.severity import RiskScore, Severity

__all__ = [
    "Severity",
    "RiskScore",
    "IPAddress",
    "DomainName",
    "Hostname",
    "URL",
    "Port",
    "Service",
    "Protocol",
    "AssetIdentifier",
    "Scope",
]
