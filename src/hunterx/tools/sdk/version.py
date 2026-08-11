# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Version manager.

Tracks the installed version of each tool and validates requested versions
against the installed one. Provides the version facts consumed by the health
checker, installer and execution context.
"""

from __future__ import annotations

import re

_SEMVER = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$")
_CONSTRAINT = re.compile(r"^(>=|<=|==|>|<)\s*(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?)$")


class VersionManager:
    """Maintain the installed version map for tools.

    Usage::

        versions = VersionManager()
        versions.record("nmap", "7.94")
        versions.installed("nmap")            # "7.94"
        versions.satisfies("nmap", ">=7.80")  # True
    """

    def __init__(self) -> None:
        self._versions: dict[str, str] = {}

    def record(self, tool_id: str, version: str) -> None:
        """Record the installed ``version`` for ``tool_id``."""
        self._versions[tool_id] = version

    def installed(self, tool_id: str) -> str | None:
        """Return the recorded version, or ``None`` when unknown."""
        return self._versions.get(tool_id)

    def is_known(self, tool_id: str) -> bool:
        """Return ``True`` when a version is recorded."""
        return tool_id in self._versions

    def satisfies(self, tool_id: str, requirement: str | None) -> bool:
        """Return ``True`` when the installed version meets ``requirement``.

        ``requirement`` may be empty/``None`` (always satisfied when a version
        is recorded), a bare ``x.y.z`` version (exact match) or an operator
        constraint (``>=x.y.z``, ``>``, ``==``, ``<=``, ``<``). Unknown
        versions never satisfy a constraint.
        """
        version = self._versions.get(tool_id)
        if not version or not _SEMVER.match(version):
            return False
        if not requirement:
            return True
        match = _CONSTRAINT.match(requirement.strip())
        if not match:
            return requirement == version
        operator, target = match.group(1), match.group(2)
        if not _SEMVER.match(target):
            return requirement == version
        comparison = _compare(version, target)
        operators = {">": comparison > 0, ">=": comparison >= 0, "==": comparison == 0, "<": comparison < 0, "<=": comparison <= 0}
        return operators[operator]

    def all(self) -> dict[str, str]:
        """Return a copy of the version map."""
        return dict(self._versions)


def _compare(left: str, right: str) -> int:
    def _key(part: str) -> tuple[int, ...]:
        numbers: list[int] = []
        for chunk in part.split("."):
            digits = "".join(ch for ch in chunk if ch.isdigit())
            numbers.append(int(digits) if digits else 0)
        while len(numbers) < 3:
            numbers.append(0)
        return tuple(numbers)

    lhs, rhs = _key(left), _key(right)
    if lhs == rhs:
        return 0
    return 1 if lhs > rhs else -1
