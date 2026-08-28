# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal capability-finding lifecycle (Phase 6).

Turns a capability-execution finding (Phase 5) into a validated, reportable
finding through the existing HunterX finding lifecycle: replay, reproduction,
impact, PoC, severity and remediation — reusing the canonical finding schema.
"""

from hunterx.domain.capability_finding.enums import ReproductionVerdict
from hunterx.domain.capability_finding.lifecycle import (
    PHASE_SIX_STAGES,
    ReproductionClassifier,
    stage_for_state,
)
from hunterx.domain.capability_finding.models import (
    CapabilityCandidate,
    Remediation,
    ReplayAttempt,
    RequestReconstruction,
)
from hunterx.domain.capability_finding.remediation import RemediationGuide
from hunterx.domain.capability_finding.replay import ReplayEngine
from hunterx.domain.capability_finding.severity import EvidenceSeverityEngine

__all__ = [
    "PHASE_SIX_STAGES",
    "CapabilityCandidate",
    "EvidenceSeverityEngine",
    "Remediation",
    "RemediationGuide",
    "ReplayAttempt",
    "ReplayEngine",
    "ReproductionClassifier",
    "ReproductionVerdict",
    "RequestReconstruction",
    "stage_for_state",
]
