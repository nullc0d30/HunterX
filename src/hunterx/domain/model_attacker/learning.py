# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Model learning context: contradictions, findings and adjacent attack paths.

Contradictions and validated findings are first-class reasoning inputs. A
contradicted hypothesis is never re-run (its fingerprint is remembered as
disproven), and a validated finding expands the search: the affected surface's
related endpoints, objects and parameters become candidate adjacent paths for
the next reasoning round. Chaining is evidence-derived here — the concrete
hypotheses are always produced by the connected model from this context.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass
class LearningContext:
    """Accumulates the evidence the model reasons over."""

    disproven_fingerprints: set[str] = field(default_factory=set)
    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    adjacent_paths: list[dict[str, Any]] = field(default_factory=list)
    updated_at: str = field(default_factory=utcnow_iso)

    def record_observation(self, *, hypothesis_id: str, capability: str, surface: str, signal: str, supported: bool) -> None:
        """Record an attack observation (supporting or contradicting)."""
        self.observations.append(
            {
                "observation_id": generate_id(),
                "hypothesis_id": hypothesis_id,
                "capability": capability,
                "surface": surface,
                "signal": signal,
                "supported": supported,
                "recorded_at": utcnow_iso(),
            }
        )
        self.updated_at = utcnow_iso()

    def remember_disproven(self, fingerprint: str) -> None:
        """Remember a disproven hypothesis so it is never re-run."""
        self.disproven_fingerprints.add(fingerprint)
        self.updated_at = utcnow_iso()

    def record_finding(self, finding: dict[str, Any], *, related: list[dict[str, Any]]) -> None:
        """Record a validated finding and its derived adjacent attack paths."""
        self.validated_findings.append(finding)
        self.adjacent_paths.extend(related)
        self.updated_at = utcnow_iso()

    def summary(self) -> dict[str, Any]:
        """Return the compact context the model reasons over (JSON-safe)."""
        return {
            "disproven_hypotheses": sorted(self.disproven_fingerprints),
            "validated_findings": [dict(item) for item in self.validated_findings],
            "observations": [dict(item) for item in self.observations],
            "adjacent_paths": [dict(item) for item in self.adjacent_paths],
            "updated_at": self.updated_at,
        }


def adjacent_paths_for(finding: dict[str, Any], surface_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive candidate adjacent attack paths from a validated finding.

    Evidence-derived: the finding's surface keeps its parameters, the surface's
    sibling endpoints carry the same parameters, and the finding's capability
    may apply to the sibling endpoints. The model turns these candidates into
    concrete hypotheses — the paths are never hardcoded chains.
    """
    surface = str(finding.get("surface") or finding.get("endpoint") or "")
    capability = str(finding.get("capability") or "")
    vector = str(finding.get("vector") or "")
    paths: list[dict[str, Any]] = []
    for node in surface_nodes:
        endpoint = str(node.get("surface") or node.get("endpoint") or "")
        parameters = tuple(str(p) for p in node.get("parameters") or ())
        if not endpoint:
            continue
        if endpoint == surface:
            for param in parameters:
                if param != vector:
                    paths.append({"capability": capability, "surface": endpoint, "attack_vector": param, "reason": "adjacent parameter on the affected surface"})
        elif parameters and capability:
            paths.append({"capability": capability, "surface": endpoint, "attack_vector": parameters[0], "reason": "sibling endpoint carrying the same input shape"})
    return paths


__all__ = ["LearningContext", "adjacent_paths_for"]
