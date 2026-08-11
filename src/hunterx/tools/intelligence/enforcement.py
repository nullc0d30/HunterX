# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool enforcement engine (Sprint 023).

The enforcement engine is the gatekeeper that runs *before* a tool executes.
It validates the invocation against the tool's typed input schema and
invocation contract, enforces the safety ceiling against the mission
authorization, verifies scope containment, applies rate-limit and resource
budgets, and detects prompt-injection patterns in AI-derived input values.

Invalid input MUST fail before execution — never inside the tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from hunterx.domain.exceptions import (
    AuthorizationError,
    OperationError,
)
from hunterx.domain.exceptions.base import HunterXErrorCode
from hunterx.domain.tool_intelligence import (
    ToolInputField,
    ToolInputSchema,
    ToolInvocationContract,
    ToolRateLimitProfile,
    ToolResourceRequirements,
    ToolSafetyClass,
    ToolSafetyProfile,
)


class EnforcementViolation(OperationError):  # noqa: N818 - widely referenced legacy name
    """Raised when an execution fails a pre-execution enforcement gate."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, gate: str, detail: str) -> None:
        super().__init__(f"Tool '{tool_id}' failed {gate}: {detail}")
        self.tool_id = tool_id
        self.gate = gate
        self.detail = detail


@dataclass(frozen=True, slots=True)
class EnforcementResult:
    """Outcome of an enforcement gate evaluation."""

    allowed: bool
    gate: str
    detail: str = ""
    effective_rate_limit: ToolRateLimitProfile | None = None


@dataclass
class _RateLimitState:
    """In-memory per-tool rate-limit state (requests/sec, concurrency)."""

    _started_at: float = 0.0
    _window_requests: int = 0
    _active: int = 0


class ToolEnforcementEngine:
    """Enforce safety, scope, rate-limit, resource and input-integrity gates.

    Usage::

        engine = ToolEnforcementEngine()
        engine.enforce_safety("nuclei", authorization=ToolSafetyClass.ACTIVE)
        engine.validate_inputs("nuclei", schema, {"url": "https://example.com"})
    """

    def __init__(self) -> None:
        self._injection_patterns = _default_injection_patterns()
        self._rate_state: dict[str, _RateLimitState] = {}

    # -- gates -------------------------------------------------------------

    def enforce_safety(
        self,
        tool_id: str,
        *,
        authorization: ToolSafetyClass,
        safety: ToolSafetyProfile | None = None,
        authorization_granted: bool = False,
    ) -> None:
        """Raise :class:`EnforcementViolation` when the safety gate fails.

        A tool whose safety class exceeds the authorization ceiling, or that
        requires authorization without approval, must never execute.
        """
        if safety is None:
            return
        if safety.safety_class.exceeds(authorization):
            raise EnforcementViolation(
                tool_id,
                "safety gate",
                f"safety class {safety.safety_class.value} exceeds authorization "
                f"{authorization.value}",
            )
        if safety.requires_authorization and not authorization_granted:
            raise AuthorizationError(
                f"Tool '{tool_id}' requires authorization before execution."
            )

    def validate_inputs(
        self,
        tool_id: str,
        schema: ToolInputSchema | None,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate ``values`` against ``schema``; return validated values.

        Enforces required fields, kind coercion, choices and regex patterns.
        Also scans string values for prompt-injection patterns.

        Raises:
            EnforcementViolation: on missing/type-invalid/pattern-violating
                or injection-bearing input.

        """
        if schema is None:
            for key, value in values.items():
                if isinstance(value, str):
                    self._guard_injection(tool_id, key, value)
                    self._guard_shell_metacharacters(tool_id, key, value)
            return dict(values)

        for field_name in schema.required:
            if field_name not in values or values[field_name] in (None, ""):
                raise EnforcementViolation(
                    tool_id, "input gate", f"required input '{field_name}' is missing"
                )

        validated: dict[str, Any] = {}
        for field in schema.fields:
            if field.name not in values:
                if field.required:
                    raise EnforcementViolation(
                        tool_id, "input gate", f"required field '{field.name}' is missing"
                    )
                if field.default is not None:
                    validated[field.name] = field.default
                continue
            value = values[field.name]
            value = self._coerce(tool_id, field, value)
            if isinstance(value, str):
                self._guard_injection(tool_id, field.name, value)
                self._guard_shell_metacharacters(tool_id, field.name, value)
            validated[field.name] = value

        for name, value in values.items():
            if name not in validated:
                if isinstance(value, str):
                    self._guard_injection(tool_id, name, value)
                    self._guard_shell_metacharacters(tool_id, name, value)
                validated[name] = value
        return validated

    def enforce_scope(
        self,
        tool_id: str,
        *,
        target: str,
        authorized_scope: tuple[str, ...],
        scope_profile=None,
    ) -> None:
        """Raise when ``target`` is not inside ``authorized_scope``.

        A tool adapter can never widen scope; this gate ensures the execution
        target is contained before the tool ever runs. Containment covers
        exact matches, prefix scopes (``https://api.example.com``) and domain
        suffix containment (``api.example.com`` is inside ``example.com``).
        """
        if not authorized_scope:
            return
        for prefix in authorized_scope:
            prefix = prefix.rstrip("*")
            if target == prefix or target.startswith(prefix):
                return
            if _is_domain_scope(prefix) and _within_domain(target, prefix):
                return
        raise EnforcementViolation(
            tool_id,
            "scope gate",
            f"target '{target}' is outside authorized scope {authorized_scope}",
        )

    def check_rate_limit(
        self,
        tool_id: str,
        *,
        declared: ToolRateLimitProfile | None,
        mission_limits: ToolRateLimitProfile | None = None,
        scope_limits: ToolRateLimitProfile | None = None,
    ) -> ToolRateLimitProfile:
        """Compute the effective rate limit (min of all applicable limits)."""
        effective = _merge_limits(declared, mission_limits, scope_limits)
        state = self._rate_state.setdefault(tool_id, _RateLimitState())
        if effective.requests_per_second > 0 and state._window_requests >= effective.requests_per_second:
            raise EnforcementViolation(
                tool_id,
                "rate-limit gate",
                f"sustained rate exceeds {effective.requests_per_second:g} req/s",
            )
        if effective.concurrency > 0 and state._active >= effective.concurrency:
            raise EnforcementViolation(
                tool_id,
                "rate-limit gate",
                f"concurrency exceeds {effective.concurrency}",
            )
        state._window_requests += 1
        state._active += 1
        return effective

    def enforce_resources(
        self,
        tool_id: str,
        *,
        required: ToolResourceRequirements | None,
        available_memory_mb: float = 0.0,
        available_disk_mb: float = 0.0,
    ) -> None:
        """Raise when declared resource needs exceed the available budget."""
        if required is None:
            return
        if available_memory_mb > 0 and required.memory_estimate_mb > available_memory_mb:
            raise EnforcementViolation(
                tool_id,
                "resource gate",
                f"needs {required.memory_estimate_mb:g} MB memory, only "
                f"{available_memory_mb:g} MB available",
            )
        if available_disk_mb > 0 and required.disk_estimate_mb > available_disk_mb:
            raise EnforcementViolation(
                tool_id,
                "resource gate",
                f"needs {required.disk_estimate_mb:g} MB disk, only "
                f"{available_disk_mb:g} MB available",
            )

    def validate_invocation(
        self,
        tool_id: str,
        contract: ToolInvocationContract | None,
        values: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate argument values against an invocation contract.

        Arguments are typed structured values — never concatenated strings
        built from AI-generated input. This gate rejects values that contain
        shell metacharacters in fields that forbid them.
        """
        if contract is None:
            return values
        validated: dict[str, Any] = {}
        declared = {arg.name: arg for arg in contract.arguments}
        for name, value in values.items():
            field = declared.get(name)
            if (
                field is not None
                and field.kind in ("path", "url", "domain", "ip", "host", "port")
                and isinstance(value, str)
            ):
                self._guard_shell_metacharacters(tool_id, name, value)
            validated[name] = value
        for name, field in declared.items():
            if field.required and name not in validated:
                raise EnforcementViolation(
                    tool_id, "invocation gate", f"required argument '{name}' is missing"
                )
        return validated

    # -- internals ---------------------------------------------------------

    def _coerce(self, tool_id: str, field: ToolInputField, value: Any) -> Any:
        kind = field.kind
        try:
            if kind == "bool":
                return _as_bool(value)
            if kind in ("int", "port"):
                return int(value)
            if kind == "float":
                return float(value)
            if kind in ("list",):
                return list(value) if isinstance(value, (list, tuple)) else [value]
        except (TypeError, ValueError) as error:
            raise EnforcementViolation(
                tool_id, "input gate", f"field '{field.name}' must be a {kind}"
            ) from error

        if isinstance(value, str) and kind == "choice" and field.choices and value not in field.choices:
            raise EnforcementViolation(
                tool_id,
                "input gate",
                f"field '{field.name}' must be one of {field.choices}",
            )
        if isinstance(value, str) and field.pattern and not re.search(field.pattern, value):
            raise EnforcementViolation(
                tool_id,
                "input gate",
                f"field '{field.name}' violates pattern '{field.pattern}'",
            )
        return value

    def _guard_injection(self, tool_id: str, field_name: str, value: str) -> None:
        lowered = value.lower()
        for label, pattern in self._injection_patterns:
            if pattern.search(lowered):
                raise EnforcementViolation(
                    tool_id,
                    "prompt-injection gate",
                    f"field '{field_name}' contains a {label} pattern",
                )

    @staticmethod
    def _guard_shell_metacharacters(tool_id: str, field_name: str, value: str) -> None:
        if re.search(r"[;&|`$<>]", value):
            raise EnforcementViolation(
                tool_id,
                "invocation gate",
                f"field '{field_name}' contains shell metacharacters",
            )

    def register_injection_pattern(self, label: str, pattern: re.Pattern[str]) -> None:
        """Register a custom prompt-injection pattern."""
        self._injection_patterns.append((label, pattern))


def _default_injection_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [
        ("instruction-override", re.compile(r"\b(ignore|override|disregard) (all )?(previous|prior) (instructions?|prompts?)\b")),
        ("role-reversal", re.compile(r"\b(act|behave) as (an? )?(unrestricted|developer|god|hunterx system)\b")),
        ("prompt-leak", re.compile(r"\b(reveal|show|print|output) your (system prompt|instructions?|hidden prompt)\b")),
        ("tool-escape", re.compile(r"\b(forget|ignore) (the )?(tool|scope|safety|rules)\b")),
    ]


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return value.lower() in ("1", "true", "yes", "on")


def _is_domain_scope(prefix: str) -> bool:
    """Return ``True`` when ``prefix`` is a bare domain scope."""
    if "://" in prefix or "/" in prefix:
        return False
    return "." in prefix and not prefix.startswith(("-", "*"))


def _within_domain(target: str, scope: str) -> bool:
    """Return ``True`` when ``target`` is ``scope`` or a subdomain of it."""
    target = target.split("://", 1)[-1].split("/", 1)[0]
    if not target:
        return False
    return target == scope or target.endswith(f".{scope}")


def _merge_limits(*profiles: ToolRateLimitProfile | None) -> ToolRateLimitProfile:
    """Return the most restrictive merged rate-limit profile."""
    present = [p for p in profiles if p is not None]
    if not present:
        return ToolRateLimitProfile()
    values: dict[str, list] = {
        "requests_per_second": [p.requests_per_second for p in present],
        "concurrency": [p.concurrency for p in present],
        "burst": [p.burst for p in present],
        "cooldown_seconds": [p.cooldown_seconds for p in present],
    }
    targets: dict[str, float] = {}
    for profile in present:
        for key, value in profile.target_limits.items():
            targets[key] = min(targets.get(key, value), value)
    return ToolRateLimitProfile(
        requests_per_second=min(values["requests_per_second"]),
        concurrency=min(values["concurrency"]),
        burst=min(values["burst"]),
        cooldown_seconds=max(values["cooldown_seconds"]),
        target_limits=targets,
    )


__all__ = [
    "EnforcementViolation",
    "EnforcementResult",
    "ToolEnforcementEngine",
    "_merge_limits",
]
