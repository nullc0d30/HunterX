# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack path engine.

Identifies security-relevant chains through the attack-surface graph, scores
them with explainable dimensions and tracks their validation state. A
theoretical path is HYPOTHETICAL; a path with evidence is SUPPORTED; a path
with validated steps is VALIDATED; a path with reproducible proof is PROVED.
The states are never collapsed.

Attack paths are intelligence only — they never directly trigger execution.
The planner translates a path into authorized actions.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
    AttackPathState,
    AttackPathStepKind,
    MissionObjective,
    PathScoringDimension,
)
from hunterx.domain.adaptive_mission_planning.models import AttackPath, AttackPathStep
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph

#: Entity kinds that act as entry points (exposure).
_EXPOSURE_KINDS = frozenset(
    {
        "url",
        "api_endpoint",
        "graphql_endpoint",
        "websocket_endpoint",
        "port",
        "cloud_resource",
        "cloud_endpoint",
        "storage_resource",
        "compute_resource",
        "kubernetes_resource",
        "saas_integration",
        "webhook",
        "admin_surface",
        "auth_surface",
        "auth_endpoint",
        "service",
    }
)

#: Per-call BFS budget fallback (used when :meth:`AttackPathEngine._chains` is
#: invoked without a shared discovery budget) so no caller can trigger an
#: unbounded expansion on a dense graph. The durable system of record keeps the
#: full surface.
_MAX_CHAIN_VISITS = 10000

#: Global discovery budget for :meth:`AttackPathEngine.discover`. The attack
#: path analysis runs after EVERY meaningful observation over the mission
#: context graph; on a target with hundreds of services/endpoints an unbounded
#: analysis is a memory/CPU bomb (the real runaway was exactly this). These
#: totals keep one analysis pass deterministic and cheap; the durable system of
#: record keeps the full surface.
_MAX_ENTRY_POINTS = 40
_MAX_TOTAL_VISITS = 4000
_MAX_TOTAL_CHAINS = 400

#: Entity kind → attack-path step kind.
_KIND_TO_STEP: dict[str, AttackPathStepKind] = {
    "url": AttackPathStepKind.APPLICATION,
    "api_endpoint": AttackPathStepKind.APPLICATION,
    "graphql_endpoint": AttackPathStepKind.APPLICATION,
    "websocket_endpoint": AttackPathStepKind.APPLICATION,
    "port": AttackPathStepKind.EXPOSURE,
    "cloud_resource": AttackPathStepKind.EXPOSURE,
    "cloud_endpoint": AttackPathStepKind.EXPOSURE,
    "storage_resource": AttackPathStepKind.SENSITIVE_RESOURCE,
    "database_resource": AttackPathStepKind.SENSITIVE_RESOURCE,
    "compute_resource": AttackPathStepKind.REACHABILITY,
    "kubernetes_resource": AttackPathStepKind.REACHABILITY,
    "hostname": AttackPathStepKind.REACHABILITY,
    "ip": AttackPathStepKind.REACHABILITY,
    "service": AttackPathStepKind.SERVICE,
    "cloud_service": AttackPathStepKind.SERVICE,
    "auth_boundary": AttackPathStepKind.AUTHENTICATION_BOUNDARY,
    "auth_surface": AttackPathStepKind.AUTHENTICATION_BOUNDARY,
    "auth_endpoint": AttackPathStepKind.AUTHENTICATION_BOUNDARY,
    "identity_provider": AttackPathStepKind.AUTHENTICATION_BOUNDARY,
    "authentication_scheme": AttackPathStepKind.AUTHENTICATION_BOUNDARY,
    "authorization_endpoint": AttackPathStepKind.AUTHORIZATION_WEAKNESS,
    "authorization_resource": AttackPathStepKind.AUTHORIZATION_WEAKNESS,
    "admin_surface": AttackPathStepKind.AUTHORIZATION_WEAKNESS,
    "credential": AttackPathStepKind.CREDENTIAL_EXPOSURE,
    "secret": AttackPathStepKind.CREDENTIAL_EXPOSURE,
    "api_key": AttackPathStepKind.CREDENTIAL_EXPOSURE,
    "cloud_environment": AttackPathStepKind.CONFIGURATION_EXPOSURE,
    "vulnerability": AttackPathStepKind.VALIDATED_WEAKNESS,
    "cve": AttackPathStepKind.VALIDATED_WEAKNESS,
}

#: Interesting step kinds — paths that only wander structural nodes are dropped.
_INTERESTING_STEP_KINDS = frozenset(
    {
        AttackPathStepKind.EXPOSURE,
        AttackPathStepKind.SERVICE,
        AttackPathStepKind.APPLICATION,
        AttackPathStepKind.AUTHENTICATION_BOUNDARY,
        AttackPathStepKind.AUTHORIZATION_WEAKNESS,
        AttackPathStepKind.SENSITIVE_RESOURCE,
        AttackPathStepKind.CREDENTIAL_EXPOSURE,
        AttackPathStepKind.CONFIGURATION_EXPOSURE,
        AttackPathStepKind.VALIDATED_WEAKNESS,
    }
)

#: Default path scoring weights (sum ≈ 1.0).
DEFAULT_PATH_WEIGHTS: dict[PathScoringDimension, float] = {
    PathScoringDimension.REACHABILITY: 0.20,
    PathScoringDimension.EVIDENCE_STRENGTH: 0.20,
    PathScoringDimension.ASSET_CRITICALITY: 0.15,
    PathScoringDimension.ASSUMPTION_COUNT: 0.15,
    PathScoringDimension.VALIDATION_STATE: 0.15,
    PathScoringDimension.PROOF_AVAILABILITY: 0.10,
    PathScoringDimension.RISK: 0.05,
}


class AttackPathEngine:
    """Discover, score and track attack paths over an attack-surface graph."""

    def __init__(
        self,
        *,
        max_depth: int = 6,
        max_paths: int = 25,
        weights: dict[PathScoringDimension, float] | None = None,
    ) -> None:
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.weights = dict(DEFAULT_PATH_WEIGHTS)
        if weights:
            self.weights.update(weights)

    def discover(
        self,
        graph: AttackSurfaceGraph,
        *,
        mission_id: str = "",
        objective: MissionObjective = MissionObjective.ATTACK_SURFACE_DISCOVERY,
        evidence_map: Mapping[str, Iterable[str]] | None = None,
        validated_map: dict[str, bool] | None = None,
    ) -> list[AttackPath]:
        """Discover candidate attack paths from every exposed entry point.

        Paths are labelled with their evidence-driven state: a chain whose steps
        carry observation evidence is ``SUPPORTED`` (a genuine attack-path
        candidate), while a purely structural chain (graph adjacency only) stays
        ``HYPOTHETICAL``. The caller decides which to treat as discovered
        attacks — combinatorial adjacency alone is never a discovered attack.

        The discovery is globally budgeted (entry points, BFS visits and chains)
        so a dense surface graph can never cause an exponential expansion that
        consumes the host — a real 5.6 GiB runaway was traced to exactly this.
        """
        evidence_map = evidence_map or {}
        validated_map = validated_map or {}
        entry_points = [
            asset.key for asset in graph.assets() if _kind_str(asset.kind) in _EXPOSURE_KINDS
        ]
        budget = {"visits": _MAX_TOTAL_VISITS, "chains": _MAX_TOTAL_CHAINS}
        paths: list[AttackPath] = []
        for entry in sorted(entry_points)[:_MAX_ENTRY_POINTS]:
            if budget["visits"] <= 0:
                break
            for node_keys in self._chains(graph, entry, budget):
                steps = self._steps(graph, node_keys, evidence_map, validated_map)
                state = _path_state(steps)
                path = AttackPath(
                    mission_id=mission_id,
                    objective=objective,
                    steps=tuple(steps),
                    state=state,
                    evidence_refs=tuple(
                        ref for step in steps for ref in step.evidence_refs
                    ),
                    assumptions=tuple(
                        assumption for step in steps for assumption in step.assumptions
                    ),
                )
                self.score(path)
                paths.append(path)
                if len(paths) >= budget["chains"]:
                    break
        paths.sort(key=lambda path: (-path.score, len(path.steps)))
        return paths[: self.max_paths]

    def reassess(
        self,
        path: AttackPath,
        *,
        evidence_map: Mapping[str, Iterable[str]],
        validated_map: dict[str, bool],
        proved_map: dict[str, bool],
    ) -> AttackPath:
        """Recompute the validation state of ``path`` from current evidence."""
        steps: list[AttackPathStep] = []
        all_validated = True
        all_proved = True
        for step in path.steps:
            refs = tuple(evidence_map.get(step.asset_key, ()))
            validated = bool(validated_map.get(step.asset_key, False))
            proved = bool(proved_map.get(step.asset_key, False))
            steps.append(
                AttackPathStep(
                    asset_key=step.asset_key,
                    kind=step.kind,
                    evidence_refs=refs,
                    validated=validated or proved,
                    assumptions=step.assumptions,
                )
            )
            if not validated and not proved:
                all_validated = False
            if not proved:
                all_proved = False
        if all_proved and steps:
            path.state = AttackPathState.PROVED
            path.proved_at = _now()
        elif all_validated and steps:
            path.state = AttackPathState.VALIDATED
            path.validated_at = _now()
        elif any(step.evidence_refs for step in steps):
            path.state = AttackPathState.SUPPORTED
        else:
            path.state = AttackPathState.HYPOTHETICAL
        path.steps = tuple(steps)
        path.evidence_refs = tuple(ref for step in steps for ref in step.evidence_refs)
        path.assumptions = tuple(a for step in steps for a in step.assumptions)
        self.score(path)
        return path

    def score(self, path: AttackPath) -> AttackPath:
        """Score ``path`` with the explainable dimension weights."""
        steps = path.steps
        if not steps:
            path.score = 0.0
            path.scores = {dimension.value: 0.0 for dimension in PathScoringDimension}
            return path

        reachability = 1.0 if steps[0].kind is AttackPathStepKind.EXPOSURE else 0.5
        evidence_strength = min(1.0, len(path.evidence_refs) / max(1, len(steps)))
        criticality = 0.5
        assumptions = len(path.assumptions)
        assumption_score = 1.0 / (1.0 + assumptions) if assumptions else 1.0
        validation_state = _state_score(path.state)
        proof_availability = (
            1.0 if path.state is AttackPathState.PROVED else 0.6 if path.state is AttackPathState.VALIDATED else 0.2
        )
        risk = 0.5

        raw: dict[PathScoringDimension, float] = {
            PathScoringDimension.REACHABILITY: reachability,
            PathScoringDimension.EVIDENCE_STRENGTH: evidence_strength,
            PathScoringDimension.ASSET_CRITICALITY: criticality,
            PathScoringDimension.ASSUMPTION_COUNT: assumption_score,
            PathScoringDimension.VALIDATION_STATE: validation_state,
            PathScoringDimension.PROOF_AVAILABILITY: proof_availability,
            PathScoringDimension.RISK: risk,
        }
        total_weight = sum(self.weights.get(dimension, 0.0) for dimension in raw)
        aggregate = sum(
            self.weights.get(dimension, 0.0) * value for dimension, value in raw.items()
        )
        path.score = round(aggregate / total_weight, 4) if total_weight else 0.0
        path.scores = {dimension.value: round(value, 4) for dimension, value in raw.items()}
        return path

    # -- internals ----------------------------------------------------------

    def _chains(self, graph: AttackSurfaceGraph, start: str, budget: dict[str, int] | None = None) -> list[list[str]]:
        """BFS chains from ``start``, pruning to security-relevant step kinds.

        The BFS is budget-capped (shared across the whole discovery pass) so a
        dense attack-surface graph can never cause an exponential expansion that
        consumes the host — a real 5.6 GiB runaway was traced exactly to this
        expansion. Discovery beyond the budget is bounded to what was found.
        """
        chains: list[list[str]] = []
        queue: deque[tuple[str, list[str], set[str]]] = deque([(start, [start], {start})])
        if budget is None:
            budget = {"visits": _MAX_CHAIN_VISITS, "chains": 200}
        visits = 0
        while queue:
            if budget["visits"] <= 0 or budget["chains"] <= 0:
                break
            budget["visits"] -= 1
            visits += 1
            node, path, visited = queue.popleft()
            if len(path) - 1 >= self.max_depth:
                continue
            for neighbor in graph.neighbors(node):
                key = neighbor["key"]
                if key in visited:
                    continue
                kind = _kind_of_neighbor(neighbor)
                step_kind = _KIND_TO_STEP.get(kind)
                next_path = path + [key]
                if step_kind in _INTERESTING_STEP_KINDS:
                    chains.append(next_path)
                    budget["chains"] -= 1
                    if budget["chains"] <= 0:
                        break
                if len(next_path) - 1 < self.max_depth:
                    queue.append((key, next_path, visited | {key}))
        return chains

    def _steps(
        self,
        graph: AttackSurfaceGraph,
        node_keys: list[str],
        evidence_map: Mapping[str, Iterable[str]],
        validated_map: dict[str, bool],
    ) -> list[AttackPathStep]:
        steps: list[AttackPathStep] = []
        for key in node_keys:
            asset = graph.asset(key)
            kind = _kind_str(asset.kind) if asset is not None else ""
            step_kind = _KIND_TO_STEP.get(kind, AttackPathStepKind.REACHABILITY)
            evidence = tuple(evidence_map.get(key, ()))
            validated = bool(validated_map.get(key, False))
            assumptions: tuple[str, ...] = ()
            if not evidence and step_kind in _INTERESTING_STEP_KINDS:
                assumptions = (f"step '{key}' is inferred from graph adjacency only",)
            steps.append(
                AttackPathStep(
                    asset_key=key,
                    kind=step_kind,
                    evidence_refs=evidence,
                    validated=validated,
                    assumptions=assumptions,
                )
            )
        return steps


def _kind_str(kind: Any) -> str:
    return kind.value if hasattr(kind, "value") else str(kind)


def _kind_of_neighbor(neighbor: dict[str, Any]) -> str:
    return _kind_str(neighbor.get("kind", ""))


def _state_score(state: AttackPathState) -> float:
    return {
        AttackPathState.HYPOTHETICAL: 0.0,
        AttackPathState.SUPPORTED: 0.4,
        AttackPathState.VALIDATED: 0.8,
        AttackPathState.PROVED: 1.0,
    }.get(state, 0.0)


def _path_state(steps: list[AttackPathStep]) -> AttackPathState:
    """Return the evidence-driven state of a chain of steps.

    A chain is ``SUPPORTED`` when at least one step carries evidence refs
    (observations/hypotheses/findings); otherwise it is a purely structural
    adjacency chain and stays ``HYPOTHETICAL``. Validated/proved steps promote
    the whole path so a genuinely reproduced chain is never reported as merely
    supported.
    """
    if not steps:
        return AttackPathState.HYPOTHETICAL
    if all(step.validated for step in steps):
        return AttackPathState.VALIDATED
    if any(step.evidence_refs for step in steps):
        return AttackPathState.SUPPORTED
    return AttackPathState.HYPOTHETICAL


def _now() -> str:
    from hunterx.shared.time import utcnow_iso

    return utcnow_iso()
