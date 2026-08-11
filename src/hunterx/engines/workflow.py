# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Workflow engine.

Workflows describe the ordered, branching sequence of actions a mission runs.
This engine loads workflow definitions, validates their structure and walks
them step by step, dispatching each action to the registered executor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.exceptions import OperationError, PluginNotFoundError
from hunterx.shared.result import Failure, Result, Success


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    """A single step in a workflow definition.

    Attributes:
        id: unique step id within the workflow.
        action: tool/plugin action to execute.
        parameters: static step parameters.
        depends_on: ids of steps that must complete first.

    """

    id: str
    action: str
    parameters: dict[str, object] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WorkflowDefinition:
    """A named workflow with ordered steps."""

    name: str
    steps: tuple[WorkflowStep, ...] = ()

    def step(self, step_id: str) -> WorkflowStep | None:
        """Return a step by id or ``None``."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def validate(self) -> list[str]:
        """Return a list of structural errors (empty when valid)."""
        errors: list[str] = []
        known = {step.id for step in self.steps}
        if not self.steps:
            errors.append("workflow has no steps")
        for step in self.steps:
            if not step.action:
                errors.append(f"step '{step.id}' has no action")
            for dependency in step.depends_on:
                if dependency not in known:
                    errors.append(f"step '{step.id}' depends on unknown step '{dependency}'")
        return errors


class ExecutorPort:
    """Minimal execution contract used by the workflow engine.

    Implemented by the tool executor (``hunterx.tools.executor``); kept local
    so the workflow engine has no dependency on the tools package.
    """

    def execute_workflow_action(
        self, action: str, target: str, parameters: dict[str, object]
    ) -> Result[object, Exception]:  # pragma: no cover - interface
        """Execute a workflow action for a target and return its result."""
        raise NotImplementedError


class WorkflowEngine:
    """Load, validate and execute workflow definitions.

    Execution is topological: a step runs only after every step in
    ``depends_on`` has completed successfully. Failures halt the workflow and
    are returned as :class:`~hunterx.shared.result.Failure`.
    """

    def __init__(self, executor: ExecutorPort) -> None:
        self._executor = executor
        self._definitions: dict[str, WorkflowDefinition] = {}

    def register(self, definition: WorkflowDefinition) -> None:
        """Register a validated workflow definition."""
        errors = definition.validate()
        if errors:
            raise OperationError("Invalid workflow: " + "; ".join(errors))
        self._definitions[definition.name] = definition

    def get(self, name: str) -> WorkflowDefinition | None:
        """Return a registered workflow definition or ``None``."""
        return self._definitions.get(name)

    def list(self) -> list[str]:
        """Return the names of registered workflows."""
        return sorted(self._definitions)

    def run(
        self, workflow: str, *, targets: list[str], mission_id: str | None = None
    ) -> Result[list[object], Exception]:
        """Execute a workflow across targets, honoring step dependencies."""
        definition = self._definitions.get(workflow)
        if definition is None:
            return Failure(PluginNotFoundError(workflow))
        results: list[object] = []
        completed: set[str] = set()
        pending = list(definition.steps)
        while pending:
            progressed = False
            for step in list(pending):
                if not set(step.depends_on).issubset(completed):
                    continue
                progressed = True
                pending.remove(step)
                for target in targets:
                    outcome = self._executor.execute_workflow_action(step.action, target, dict(step.parameters))
                    if isinstance(outcome, Failure):
                        return outcome
                    results.append(outcome.value)
                completed.add(step.id)
            if not progressed:
                return Failure(OperationError("Workflow contains a dependency cycle."))
        return Success(results)
