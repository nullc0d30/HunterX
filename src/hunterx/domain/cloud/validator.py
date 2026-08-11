# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence observation validation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.cloud.models import CloudProviderObservation


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A single validation issue on an observation."""

    code: str
    message: str
    field: str = ""


@dataclass(frozen=True, slots=True)
class CloudValidationResult:
    """The result of validating one observation."""

    observation: Any
    valid: bool
    issues: tuple[ValidationIssue, ...] = ()


class CloudValidator:
    """Validate cloud observations before persistence.

    Rules are conservative: observations without a scoped origin or with a
    confidence outside ``[0, 1]`` are flagged; empty/unset subjects are
    tolerated (they may carry value in an ``indicators`` field) but never
    silently persisted for the record families that require an identifier.
    """

    _MIN_CONFIDENCE = 0.0
    _MAX_CONFIDENCE = 1.0

    def validate(self, observation: Any) -> CloudValidationResult:
        """Validate a single observation."""
        issues: list[ValidationIssue] = []
        if isinstance(observation, CloudProviderObservation) and not observation.name:
            issues.append(ValidationIssue("missing-provider", "cloud provider observation has no name", "name"))
        for name in ("identifier", "name", "endpoint", "value"):
            field_value = getattr(observation, name, None)
            if name in _REQUIRED_IF_EMPTY.get(type(observation).__name__, ()) and not str(field_value or "").strip():
                issues.append(
                    ValidationIssue(
                        f"missing-{name}",
                        f"{type(observation).__name__} requires a non-empty '{name}'",
                        name,
                    )
                )
        confidence = getattr(observation, "confidence", None)
        if confidence is not None:
            try:
                numeric = float(confidence)
            except (TypeError, ValueError):
                issues.append(ValidationIssue("bad-confidence", "confidence is not numeric", "confidence"))
            else:
                if not self._MIN_CONFIDENCE <= numeric <= self._MAX_CONFIDENCE:
                    issues.append(ValidationIssue("bad-confidence", "confidence outside [0, 1]", "confidence"))
        return CloudValidationResult(observation=observation, valid=not issues, issues=tuple(issues))

    def validate_many(self, observations: Sequence[Any]) -> list[CloudValidationResult]:
        """Validate every observation, preserving order."""
        return [self.validate(observation) for observation in observations]

    def filter_valid(self, observations: Sequence[Any]) -> list[Any]:
        """Return only valid observations."""
        return [observation for observation in observations if self.validate(observation).valid]


_REQUIRED_IF_EMPTY: dict[str, tuple[str, ...]] = {
    "CloudProviderObservation": (),
    "CloudServiceObservation": (),
    "CloudResourceObservation": ("identifier",),
    "CloudEndpointObservation": ("endpoint",),
    "CloudAccountObservation": ("value",),
    "CloudRegionObservation": ("region",),
    "CloudIdentityObservation": ("name",),
    "CloudRoleObservation": ("name",),
    "CloudPermissionObservation": ("action",),
    "SaaSProviderObservation": ("name",),
    "SaaSIntegrationObservation": ("name",),
    "WebhookObservation": ("endpoint",),
    "CloudDependencyObservation": ("name",),
    "StorageResourceObservation": ("identifier",),
    "ComputeResourceObservation": ("identifier",),
    "ContainerResourceObservation": ("identifier",),
    "DatabaseResourceObservation": ("identifier",),
    "MessageInfrastructureObservation": ("identifier",),
    "ApiGatewayResourceObservation": ("identifier",),
    "CdnResourceObservation": ("identifier",),
    "LoadBalancerResourceObservation": ("identifier",),
    "SecretManagementObservation": ("name",),
    "CloudExposureObservation": (),
}
