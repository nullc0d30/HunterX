# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin result value objects.

Typed results a plugin can return, keeping the finding/evidence schemas
canonical across all plugins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class FindingResult:
    """A finding a plugin wants recorded.

    Attributes:
        title: short title.
        severity: severity name (``low`` | ``medium`` | ``high`` | ``critical``).
        target: affected target identifier.
        description: technical description.
        risk_score: optional normalized score in ``[0, 10]``.
        metadata: extra JSON-serializable attributes.

    """

    title: str
    severity: str
    target: str
    description: str = ""
    risk_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class EvidenceResult:
    """Supporting evidence a plugin wants attached to a finding.

    Attributes:
        content: raw evidence content.
        mime_type: content type.

    """

    content: str
    mime_type: str = "text/plain"


#: Convenience marker for the set of structured result types.
PluginResultTypes = (FindingResult, EvidenceResult)
