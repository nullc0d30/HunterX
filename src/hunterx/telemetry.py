# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Telemetry facade."""

from __future__ import annotations

from hunterx.domain.ports.services import TelemetryPort
from hunterx.infrastructure.telemetry import MemoryTelemetry

__all__ = ["TelemetryPort", "MemoryTelemetry"]
