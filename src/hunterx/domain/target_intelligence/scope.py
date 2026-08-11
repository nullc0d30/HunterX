# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Intelligence scope & isolation enforcement.

Sprint 026. Target intelligence MUST be isolated by tenant, mission, scope and
authorization context — no cross-target leakage, no cross-mission
contamination. The enforcer validates that observations, assets and changes are
only ingested into their authorized scope, and that reads never span tenants.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceTarget,
    Observation,
)


class ScopeViolationError(Exception):
    """Raised when an intelligence item violates scope or isolation.

    Attributes:
        reason: human-readable violation reason.
        target_id: the target the violation concerned (``""`` when unknown).

    """

    def __init__(self, reason: str, *, target_id: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.target_id = target_id


@dataclass(frozen=True, slots=True)
class TargetIsolationContext:
    """The authorization context an intelligence operation runs under.

    Attributes:
        tenant: tenant key (``""`` = default tenant).
        mission_id: owning mission.
        scope: scope identifier (authorized scope).
        target_id: owning target.

    """

    tenant: str = ""
    mission_id: str = ""
    scope: str = ""
    target_id: str = ""

    def allows_target(self, target: IntelligenceTarget) -> bool:
        """Return ``True`` when the context may operate on ``target``."""
        tenant_blocked = self.tenant and target.tenant and self.tenant != target.tenant
        mission_blocked = self.mission_id and target.mission_id and self.mission_id != target.mission_id
        return not (tenant_blocked or mission_blocked)


class TargetIntelligenceScopeEnforcer:
    """Enforce tenant/mission/scope isolation on intelligence ingestion."""

    def __init__(self, context: TargetIsolationContext | None = None) -> None:
        self.context = context or TargetIsolationContext()

    def check_target(self, target: IntelligenceTarget) -> IntelligenceTarget:
        """Validate that the context may operate on the target."""
        if not self.context.allows_target(target):
            raise ScopeViolationError(
                "target is outside the tenant/mission isolation context",
                target_id=target.target_id,
            )
        return target

    def check_observation(self, observation: Observation) -> Observation:
        """Validate an observation against the isolation context."""
        if self.context.mission_id and observation.mission_id and observation.mission_id != self.context.mission_id:
            raise ScopeViolationError(
                "observation mission_id does not match the isolation context",
                target_id=observation.target_id,
            )
        if self.context.target_id and observation.target_id != self.context.target_id:
            raise ScopeViolationError(
                "observation target_id does not match the isolation context",
                target_id=observation.target_id,
            )
        return observation

    def check_asset(self, asset: IntelligenceAsset) -> IntelligenceAsset:
        """Validate an asset against the isolation context."""
        if self.context.mission_id and asset.mission_id and asset.mission_id != self.context.mission_id:
            raise ScopeViolationError(
                "asset mission_id does not match the isolation context",
                target_id=asset.target_id,
            )
        if self.context.target_id and asset.target_id != self.context.target_id:
            raise ScopeViolationError(
                "asset target_id does not match the isolation context",
                target_id=asset.target_id,
            )
        return asset

    def enforce_in_scope(self, *, asset_key: str, value: str) -> bool:
        """Return ``True`` when an observed value stays inside the scope.

        The scope string is interpreted as a set of authorized root identifiers
        (domains, CIDRs, account ids). Hosts outside the roots are
        ``False``.
        """
        if not self.context.scope:
            return True
        roots = {root.strip() for root in self.context.scope.split(",") if root.strip()}
        if not roots:
            return True
        lowered = value.lower()
        for root in roots:
            root_lower = root.lower()
            if root_lower in lowered or lowered.endswith(f".{root_lower}"):
                return True
        return False


__all__ = [
    "ScopeViolationError",
    "TargetIntelligenceScopeEnforcer",
    "TargetIsolationContext",
]
