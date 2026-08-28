# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability execution — authoritative coverage records.

Phase 5: universal capability execution. Every registered capability must be
demonstrably DISCOVERED -> MAPPED -> SCHEDULED -> EXECUTED -> ANALYZED ->
VERIFIED against every applicable surface — or honestly marked otherwise. A
capability is never considered implemented merely because its class exists in
source code.

Each capability carries exactly one authoritative mission-level status:

    FINDING         at least one applicable surface produced a supported
                    (class-specific) probe verdict — evidence of the class.
    VERIFIED        the capability executed end-to-end on every applicable
                    surface and the probes produced definite negative
                    verdicts (contradicted) — execution verified, no finding.
    NO_FINDING      the capability executed but the probes produced no
                    definitive signal (uninformative) — tested, nothing
                    confirmed either way.
    NOT_APPLICABLE  target evidence supports non-applicability (the
                    capability never mapped to a discovered surface
                    characteristic).
    BLOCKED         the capability could not complete (probe refused on a
                    non-loopback target, no probe constructible, or a mapped
                    task never executed).
    FAILED          execution or analysis failed.

    BLOCKED != COMPLETE, FAILED != COMPLETE, UNAVAILABLE != NOT_APPLICABLE.
"""

from __future__ import annotations

from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.capability_execution.models import (
    CapabilityCoverage,
    CapabilityExecutionRecord,
    ToolExecutionRecord,
    aggregate_status,
    build_capability_coverage,
)

__all__ = [
    "CapabilityCoverage",
    "CapabilityExecutionRecord",
    "CapabilityExecutionStatus",
    "ToolExecutionRecord",
    "aggregate_status",
    "build_capability_coverage",
]
