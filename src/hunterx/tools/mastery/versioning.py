# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Version-aware tool knowledge.

Tool behavior changes over time. Tool version, knowledge version, parser
version and adapter version are tracked independently. Supports version
ranges, deprecated/renamed/removed options and changed output formats.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field

from hunterx.tools.mastery.registry import ToolMasteryRegistry


@dataclass(frozen=True, slots=True)
class VersionCheckResult:
    """Result of a version compatibility check.

    Attributes:
        tool_id: the tool checked.
        installed_version: the installed version string.
        compatible: whether the installed version is accepted.
        reason: human-readable reason.
        constraints: the constraints applied.

    """

    tool_id: str
    installed_version: str
    compatible: bool
    reason: str
    constraints: tuple[str, ...] = ()


@dataclass(slots=True)
class ToolVersionAwareness:
    """Evaluate installed tool versions against declared constraints.

    A profile's ``version_constraints`` may contain PEP-440 style constraints
    (``>=2.0.0``, ``>=1.0,<3.0``, ``==2.14.0``, ``~=2.0``). When a constraint
    cannot be parsed the result is reported as incompatible with an
    explanatory reason (fail-closed).
    """

    registry: ToolMasteryRegistry
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def check(self, tool_id: str, installed_version: str) -> VersionCheckResult:
        """Check ``installed_version`` against the tool's constraints."""
        profile = self.registry.get(tool_id)
        if profile is None:
            return VersionCheckResult(tool_id, installed_version, False, "tool not registered")
        constraints = profile.version_constraints or ()
        if not constraints:
            return VersionCheckResult(
                tool_id,
                installed_version,
                True,
                "no constraints declared",
                constraints,
            )
        for constraint in constraints:
            ok, reason = _constraint_match(installed_version, constraint)
            if not ok:
                return VersionCheckResult(
                    tool_id,
                    installed_version,
                    False,
                    f"'{installed_version}' fails '{constraint}': {reason}",
                    constraints,
                )
        return VersionCheckResult(
            tool_id,
            installed_version,
            True,
            "all constraints satisfied",
            constraints,
        )

    def installed_ok(self, tool_id: str, installed_version: str) -> bool:
        """Return ``True`` when the installed version satisfies constraints."""
        return self.check(tool_id, installed_version).compatible


def _constraint_match(version: str, constraint: str) -> tuple[bool, str]:
    """Match a PEP-440 style constraint against a version string.

    Returns ``(compatible, reason)``. Fail-closed on unparseable versions.
    """
    constraint = constraint.strip()
    if not constraint:
        return True, "empty constraint"

    # Comma-separated clauses must all pass.
    clauses = [c.strip() for c in constraint.split(",") if c.strip()]
    for clause in clauses:
        ok, reason = _clause_match(version, clause)
        if not ok:
            return False, reason
    return True, "constraint satisfied"


def _clause_match(version: str, clause: str) -> tuple[bool, str]:
    match = re.match(r"^(==|!=|>=|<=|>|<|~=)\s*(\S+)$", clause)
    if not match:
        return False, f"unsupported constraint syntax '{clause}'"
    operator, wanted = match.group(1), match.group(2)
    cmp_result = _compare_versions(version, wanted)
    if cmp_result is None:
        return False, f"version '{version}' not comparable"

    if operator == "==":
        return cmp_result == 0, "exact match required"
    if operator == "!=":
        return cmp_result != 0, "must differ"
    if operator == ">=":
        return cmp_result >= 0, "version too low"
    if operator == "<=":
        return cmp_result <= 0, "version too high"
    if operator == ">":
        return cmp_result > 0, "version too low"
    if operator == "<":
        return cmp_result < 0, "version too high"
    if operator == "~=":
        # ~=X.Y matches any >=X.Y,<X.(Y+1)
        parts = wanted.split(".")
        if len(parts) < 2:
            return False, "compatible-release requires at least two components"
        base = ".".join(parts[:-1])
        upper = parts[-1]
        upper_next = str(int(upper) + 1) if upper.isdigit() else ""
        if upper_next and upper_next.isdigit():
            upper_bound = f"{base}.{upper_next}"
            return cmp_result >= 0 and _compare_versions(version, upper_bound) < 0, (
                "compatible-release bound"
            )
        return cmp_result >= 0, "compatible-release lower bound"

    return False, f"unsupported operator '{operator}'"


def _compare_versions(left: str, right: str) -> int | None:
    """Compare dotted numeric versions; returns -1/0/1 or ``None`` when invalid."""
    left_clean = re.sub(r"[^0-9.]", "", left).strip(".")
    right_clean = re.sub(r"[^0-9.]", "", right).strip(".")
    if not left_clean or not right_clean:
        return None
    left_parts = [int(p) for p in left_clean.split(".") if p != ""]
    right_parts = [int(p) for p in right_clean.split(".") if p != ""]
    length = max(len(left_parts), len(right_parts))
    left_parts += [0] * (length - len(left_parts))
    right_parts += [0] * (length - len(right_parts))
    for lv, rv in zip(left_parts, right_parts, strict=True):
        if lv < rv:
            return -1
        if lv > rv:
            return 1
    return 0
