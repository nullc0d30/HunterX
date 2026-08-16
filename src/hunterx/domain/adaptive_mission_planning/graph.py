# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive execution graph.

A living, dynamically modifiable execution graph of :class:`ActionNode`
entries connected by typed :class:`DynamicDependency` edges and
:class:`ConditionalBranch` constructs. The graph is the mission plan: it is
never a static list of commands. Replanning mutates it through
:class:`~hunterx.domain.adaptive_mission_planning.models.PlanDelta` changes.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    DependencyKind,
    PlanDeltaKind,
)
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    ConditionalBranch,
    DynamicDependency,
    PlanDelta,
    PlanDeltaChange,
)


class InvalidExecutionGraphError(Exception):
    """Raised when the execution graph is structurally invalid."""


class AdaptiveExecutionGraph:
    """A dynamic DAG of action nodes with typed dependencies and branches.

    Attributes:
        actions: index of action id → :class:`ActionNode`.
        dependencies: index of dependency id → :class:`DynamicDependency`.
        branches: index of branch id → :class:`ConditionalBranch`.

    """

    def __init__(self, *, actions: list[ActionNode] | None = None) -> None:
        self.actions: dict[str, ActionNode] = {}
        self.dependencies: dict[str, DynamicDependency] = {}
        self.branches: dict[str, ConditionalBranch] = {}
        if actions:
            for action in actions:
                self.add_action(action)

    # -- mutation -----------------------------------------------------------

    def add_action(self, action: ActionNode) -> ActionNode:
        """Register (or replace) an action node."""
        self.actions[action.action_id] = action
        return action

    def remove_action(self, action_id: str) -> bool:
        """Remove an action and every edge referencing it."""
        removed = self.actions.pop(action_id, None) is not None
        self.dependencies = {
            dep_id: dep
            for dep_id, dep in self.dependencies.items()
            if dep.source_action_id != action_id and dep.target_action_id != action_id
        }
        self.branches = {
            branch_id: branch
            for branch_id, branch in self.branches.items()
            if action_id not in branch.then_action_ids and action_id not in branch.else_action_ids
        }
        return removed

    def add_dependency(self, dependency: DynamicDependency) -> DynamicDependency:
        """Register a typed dependency, validating both endpoints exist."""
        if dependency.source_action_id not in self.actions:
            raise InvalidExecutionGraphError(
                f"dependency references unknown source action '{dependency.source_action_id}'"
            )
        if dependency.target_action_id not in self.actions:
            raise InvalidExecutionGraphError(
                f"dependency references unknown target action '{dependency.target_action_id}'"
            )
        if self._introduces_cycle(dependency.source_action_id, dependency.target_action_id):
            raise InvalidExecutionGraphError(
                f"dependency from '{dependency.source_action_id}' to "
                f"'{dependency.target_action_id}' introduces a cycle"
            )
        self.dependencies[dependency.dependency_id] = dependency
        return dependency

    def add_branch(self, branch: ConditionalBranch) -> ConditionalBranch:
        """Register a conditional branch."""
        self.branches[branch.branch_id] = branch
        return branch

    def apply_delta(self, delta: PlanDelta) -> list[str]:
        """Apply a :class:`PlanDelta` to the graph; returns affected action ids.

        The full mission is never rebuilt — only the changed nodes are
        touched. Applying a delta does not increment any version here; the
        engine owns versioning.
        """
        affected: list[str] = []
        for change in delta.changes:
            action_id = self._apply_change(change)
            if action_id:
                affected.append(action_id)
        return affected

    # -- reads --------------------------------------------------------------

    def action(self, action_id: str) -> ActionNode | None:
        """Return an action by id or ``None``."""
        return self.actions.get(action_id)

    def dependency(self, dependency_id: str) -> DynamicDependency | None:
        """Return a dependency by id or ``None``."""
        return self.dependencies.get(dependency_id)

    def actions_in_status(self, status: ActionStatus) -> list[ActionNode]:
        """Return actions currently in ``status``."""
        return [action for action in self.actions.values() if action.status is status]

    def ready_actions(self, *, approved_only: bool = True) -> list[ActionNode]:
        """Return ready, non-terminal actions.

        An action is ready when its dependencies are all terminal. When
        ``approved_only`` is set, only ``APPROVED``/``SCHEDULED`` nodes are
        eligible; otherwise any non-terminal node is returned.
        """
        ready: list[ActionNode] = []
        for action in self.actions.values():
            if action.status.is_terminal:
                continue
            if approved_only and action.status not in (ActionStatus.APPROVED, ActionStatus.SCHEDULED):
                continue
            blockers = self.direct_dependencies(action.action_id)
            if all(
                (blocker := self.action(dep.source_action_id)) is not None
                and blocker.status.is_terminal
                for dep in blockers
            ):
                ready.append(action)
        return ready

    def has_identical_action(self, node: ActionNode, *, include_terminal: bool = True) -> bool:
        """Return ``True`` when a materially identical action already exists.

        Replay protection for the planner: an action that shares ``node``'s
        identity (capability, asset, hypothesis, parameter/technology context
        and tool) must not be scheduled again unless new state changed the
        identity. ``include_terminal`` controls whether already-completed (or
        otherwise terminal) actions still count — the default keeps them in
        play so a fully executed action is never silently re-run.
        """
        key = node.identity_key()
        if not key:
            return False
        for existing in self.actions.values():
            if not include_terminal and existing.status.is_terminal:
                continue
            if existing.identity_key() == key:
                return True
        return False

    def completed_identical(self, node: ActionNode) -> list[ActionNode]:
        """Return already-completed actions sharing ``node``'s identity.

        A ready action whose identity was already executed is a *replay*: it
        must be invalidated (the repeated branch dropped) so the planner moves
        to another actionable branch instead of executing it again.
        """
        key = node.identity_key()
        if not key:
            return []
        return [
            existing
            for existing in self.actions.values()
            if existing.status is ActionStatus.COMPLETED and existing.identity_key() == key
        ]

    def direct_dependencies(self, action_id: str) -> list[DynamicDependency]:
        """Return dependencies whose target is ``action_id``."""
        return [dep for dep in self.dependencies.values() if dep.target_action_id == action_id]

    def direct_dependants(self, action_id: str) -> list[DynamicDependency]:
        """Return dependencies whose source is ``action_id``."""
        return [dep for dep in self.dependencies.values() if dep.source_action_id == action_id]

    def topological_order(self) -> list[str]:
        """Return action ids in a valid dependency order (Kahn's algorithm).

        ``DEPENDS_ON`` edges are treated as ordering constraints; other
        dependency kinds (``enables``, ``invalidates``, ``blocks``, ...) do
        not order execution.
        """
        order: list[str] = []
        pending: dict[str, set[str]] = {node_id: set() for node_id in self.actions}
        for dep in self.dependencies.values():
            if dep.kind is DependencyKind.DEPENDS_ON and dep.source_action_id != dep.target_action_id:
                pending.setdefault(dep.target_action_id, set()).add(dep.source_action_id)
        ready = [node_id for node_id, deps in pending.items() if not deps]
        while ready:
            node_id = ready.pop(0)
            if node_id in order:
                continue
            order.append(node_id)
            for candidate, deps in pending.items():
                if node_id in deps:
                    deps.discard(node_id)
                    if not deps and candidate not in order:
                        ready.append(candidate)
        return order

    def parallel_groups(self) -> list[list[str]]:
        """Return action ids grouped into waves of concurrently runnable nodes.

        A node joins a wave when every ``DEPENDS_ON`` predecessor is complete;
        nodes with no ordering edges are grouped into the first waves.
        """
        groups: list[list[str]] = []
        completed: set[str] = set()
        remaining = {
            node_id: {
                dep.source_action_id
                for dep in self.dependencies.values()
                if dep.kind is DependencyKind.DEPENDS_ON and dep.target_action_id == node_id
            }
            for node_id in self.actions
        }
        while True:
            wave = [
                node_id
                for node_id, deps in remaining.items()
                if not deps and node_id not in completed
            ]
            if not wave:
                break
            groups.append(wave)
            completed.update(wave)
            for deps in remaining.values():
                deps.difference_update(wave)
        return groups

    def successors(self, action_id: str) -> list[str]:
        """Return ids of actions that directly depend on ``action_id``."""
        return [
            dep.target_action_id
            for dep in self.dependencies.values()
            if dep.kind is DependencyKind.DEPENDS_ON and dep.source_action_id == action_id
        ]

    def validate(self) -> list[str]:
        """Return structural errors (empty when the graph is sound)."""
        errors: list[str] = []
        known = set(self.actions)
        seen: set[str] = set()
        for action in self.actions.values():
            if action.action_id in seen:
                errors.append(f"action '{action.action_id}' registered twice")
            seen.add(action.action_id)
        for dep in self.dependencies.values():
            if dep.source_action_id not in known:
                errors.append(f"dependency '{dep.dependency_id}' references unknown source '{dep.source_action_id}'")
            if dep.target_action_id not in known:
                errors.append(f"dependency '{dep.dependency_id}' references unknown target '{dep.target_action_id}'")
        for branch in self.branches.values():
            for action_id in (*branch.then_action_ids, *branch.else_action_ids):
                if action_id and action_id not in known:
                    errors.append(f"branch '{branch.branch_id}' references unknown action '{action_id}'")
            if branch.goto_action_id and branch.goto_action_id not in known:
                errors.append(f"branch '{branch.branch_id}' GOTO references unknown action '{branch.goto_action_id}'")
        return errors

    def branch_for(self, action_id: str) -> ConditionalBranch | None:
        """Return the branch that schedules ``action_id`` (if any)."""
        for branch in self.branches.values():
            if action_id in branch.then_action_ids or action_id in branch.else_action_ids:
                return branch
        return None

    def summary(self) -> dict[str, Any]:
        """Return a JSON-safe summary of the graph."""
        return {
            "action_count": len(self.actions),
            "dependency_count": len(self.dependencies),
            "branch_count": len(self.branches),
            "ready": [action.action_id for action in self.ready_actions()],
            "topological_order": self.topological_order(),
        }

    # -- internals ----------------------------------------------------------

    def _apply_change(self, change: PlanDeltaChange) -> str | None:
        if change.kind is PlanDeltaKind.ADD_ACTION and change.node is not None:
            self.add_action(change.node)
            return change.node.action_id
        if change.kind is PlanDeltaKind.REMOVE_ACTION:
            self.remove_action(change.action_id)
            return change.action_id
        if change.kind is PlanDeltaKind.MODIFY_ACTION and change.node is not None:
            self.actions[change.node.action_id] = change.node
            return change.node.action_id
        if change.kind is PlanDeltaKind.REORDER_ACTION and change.node is not None:
            self.actions[change.node.action_id] = change.node
            return change.node.action_id
        if change.kind is PlanDeltaKind.PAUSE_ACTION:
            action = self.actions.get(change.action_id)
            if action is not None:
                action.mark(ActionStatus.PAUSED)
            return change.action_id
        if change.kind is PlanDeltaKind.RESUME_ACTION:
            action = self.actions.get(change.action_id)
            if action is not None:
                action.mark(ActionStatus.APPROVED)
            return change.action_id
        if change.kind is PlanDeltaKind.REPLACE_TOOL:
            action = self.actions.get(change.action_id)
            if action is not None and change.tool_id:
                action.selected_tool = change.tool_id
                action.touch()
            return change.action_id
        if change.kind is PlanDeltaKind.CHANGE_PRIORITY:
            action = self.actions.get(change.action_id)
            if action is not None:
                action.priority = change.priority
                action.touch()
            return change.action_id
        if change.kind is PlanDeltaKind.CREATE_BRANCH and change.branch is not None:
            self.add_branch(change.branch)
            return None
        if change.kind is PlanDeltaKind.MERGE_BRANCH:
            branch_id = change.reason or change.action_id
            if branch_id in self.branches:
                del self.branches[branch_id]
            return None
        if change.kind is PlanDeltaKind.INVALIDATE_BRANCH:
            branch = self.branches.get(change.action_id)
            if branch is not None:
                for action_id in (*branch.then_action_ids, *branch.else_action_ids):
                    node = self.actions.get(action_id)
                    if node is not None and not node.status.is_terminal:
                        node.mark(ActionStatus.SUPERSEDED)
            return change.action_id
        if change.kind is PlanDeltaKind.MARK_COMPLETE:
            action = self.actions.get(change.action_id)
            if action is not None:
                action.mark(ActionStatus.COMPLETED)
            return change.action_id
        return None

    def _introduces_cycle(self, source: str, target: str) -> bool:
        if source == target:
            return True
        # adding source -> target creates a cycle when target can already reach source
        return source in self._reachable_by_depends_on(target)

    def _reachable_by_depends_on(self, start: str) -> set[str]:
        reached: set[str] = set()
        pending = [dep.target_action_id for dep in self.dependencies.values() if dep.source_action_id == start]
        while pending:
            node_id = pending.pop(0)
            if node_id in reached:
                continue
            reached.add(node_id)
            pending.extend(
                dep.target_action_id for dep in self.dependencies.values() if dep.source_action_id == node_id
            )
        return reached
