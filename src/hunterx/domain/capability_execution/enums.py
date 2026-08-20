# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authoritative capability execution statuses."""

from __future__ import annotations

from enum import StrEnum


class CapabilityExecutionStatus(StrEnum):
    """Exactly-one authoritative status for a capability at mission level.

    A capability is NEVER considered implemented merely because its class
    exists in the catalog: the status derives from what actually executed.
    """

    FINDING = "FINDING"              # supported verdict observed somewhere
    VERIFIED = "VERIFIED"            # executed; definite negative verdicts
    NO_FINDING = "NO_FINDING"        # executed; no definitive signal
    NOT_APPLICABLE = "NOT_APPLICABLE"  # target evidence says it does not apply
    BLOCKED = "BLOCKED"              # could not complete (refused/queued/absent)
    FAILED = "FAILED"                # execution or analysis failed


#: Precedence used when aggregating per-surface outcomes into one status:
#: a finding outranks everything, then blocked/failed, then verified (definite
#: negative), then no-finding (uninformative), then not-applicable.
STATUS_PRECEDENCE: tuple[CapabilityExecutionStatus, ...] = (
    CapabilityExecutionStatus.FINDING,
    CapabilityExecutionStatus.BLOCKED,
    CapabilityExecutionStatus.FAILED,
    CapabilityExecutionStatus.VERIFIED,
    CapabilityExecutionStatus.NO_FINDING,
    CapabilityExecutionStatus.NOT_APPLICABLE,
)


__all__ = ["CapabilityExecutionStatus", "STATUS_PRECEDENCE"]
