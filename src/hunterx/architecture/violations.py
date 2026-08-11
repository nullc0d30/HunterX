# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Violation model shared across validators.

Every check emits :class:`Violation` objects. A violation carries a stable
code, a severity, the offending module/line, a human-readable message and
concrete remediation guidance so developers know exactly how to fix it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class Severity:
    """Violation severity levels (ordered, error wins)."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    _RANK = {INFO: 0, WARNING: 1, ERROR: 2}

    @classmethod
    def worst(cls, left: str, right: str) -> str:
        """Return the more severe of two severities."""
        return left if cls._RANK[left] >= cls._RANK[right] else right


@dataclass(slots=True)
class Violation:
    """A single architecture violation.

    Attributes:
        code: stable machine-readable code (e.g. ``"ARCH-001"``).
        severity: :class:`Severity` level.
        message: concise human-readable description.
        remediation: concrete guidance for fixing the violation.
        module: the offending module (may be empty).
        line: 1-based line number (0 when not applicable).
        target: the offending import target (may be empty).
        details: additional structured context.

    """

    code: str
    severity: str
    message: str
    remediation: str
    module: str = ""
    line: int = 0
    target: str = ""
    details: dict[str, object] = field(default_factory=dict)

    def key(self) -> tuple[str, str, int]:
        """Return a stable ordering key for deduplication."""
        return (self.module, self.code, self.line)

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-safe mapping."""
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "remediation": self.remediation,
            "module": self.module,
            "line": self.line,
            "target": self.target,
            "details": self.details,
        }


class ViolationCodes:
    """Canonical violation codes and their default remediation."""

    IMPORT_LAYER = "ARCH-001"
    IMPORT_FORBIDDEN = "ARCH-002"
    CIRCULAR_DEPENDENCY = "ARCH-003"
    PLUGIN_BOUNDARY = "ARCH-004"
    TOOL_BOUNDARY = "ARCH-005"
    DOCSTRING_MISSING = "ARCH-006"
    DOC_SECTION_MISSING = "ARCH-007"
    API_BREAKING = "ARCH-008"
    API_SIGNATURE = "ARCH-009"
    MODULE_OWNERSHIP = "ARCH-010"
    WAIVER_EXPIRED = "ARCH-011"
    WAIVED_ISSUE = "ARCH-100"


#: Remediation guidance keyed by code (surfaced in every report and CLI error).
REMEDIATION: dict[str, str] = {
    ViolationCodes.IMPORT_LAYER: (
        "Remove the import or invert the dependency. Dependencies must point "
        "inward toward the domain layer. Move shared logic into the owning "
        "layer, publish it as a domain port, or emit an event instead of "
        "importing internals."
    ),
    ViolationCodes.IMPORT_FORBIDDEN: (
        "This import targets a forbidden or legacy package. Remove it. "
        "Shipping code must never import legacy roots (core/, api/, the flat "
        "hunterx/ package, scripts/) or modules outside the approved "
        "dependency graph."
    ),
    ViolationCodes.CIRCULAR_DEPENDENCY: (
        "Break the cycle by extracting the shared dependency into a lower "
        "layer (usually domain or shared) that both participants import. "
        "Move the offending import behind `if TYPE_CHECKING:` only for "
        "type-only references."
    ),
    ViolationCodes.PLUGIN_BOUNDARY: (
        "Plugin packages may only import the public plugin SDK "
        "(hunterx.plugins.sdk), the domain layer and hunterx.shared. Any "
        "other hunterx import bypasses the plugin sandbox and is forbidden."
    ),
    ViolationCodes.TOOL_BOUNDARY: (
        "Tool implementations may only import the Tool Integration SDK "
        "(hunterx.tools.sdk), the domain layer and hunterx.shared. Tools must "
        "never reach into application or infrastructure internals."
    ),
    ViolationCodes.DOCSTRING_MISSING: (
        "Add a module docstring describing the module's purpose. Every "
        "public module must state what it is for before any code."
    ),
    ViolationCodes.DOC_SECTION_MISSING: (
        "Extend the module docstring with the missing section(s): "
        "Responsibilities, Dependencies and Extension points, so the module "
        "is self-documenting."
    ),
    ViolationCodes.API_BREAKING: (
        "This change removes or renames a name from the committed public API "
        "baseline (config/api_baseline.json). Restore the name or document an "
        "intentional breaking change in CHANGELOG.md and update the baseline "
        "with `hunterx-arch stability --generate`."
    ),
    ViolationCodes.API_SIGNATURE: (
        "This change alters the signature of a public callable. Adding "
        "required parameters or removing existing ones breaks callers; add "
        "new parameters with defaults instead."
    ),
    ViolationCodes.MODULE_OWNERSHIP: (
        "Move the module to the location mandated by docs/bible/"
        "03 - Folder Structure.md (see the 'What Belongs Where' decision "
        "table, section 9)."
    ),
    ViolationCodes.WAIVER_EXPIRED: (
        "A documented waiver for this issue has expired. Resolve the "
        "underlying architectural debt now and remove the waiver from "
        "config/architecture.yaml."
    ),
}
