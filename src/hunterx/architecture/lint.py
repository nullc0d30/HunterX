# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""The architecture linter.

:class:`ArchitectureLinter` is the orchestrator. It scans the package tree,
extracts imports, validates them against the dependency policy, detects cycles,
checks plugin/tool boundaries, validates documentation and compares the public
API against the committed baseline. Every check emits :class:`Violation`
objects with remediation guidance.
"""

from __future__ import annotations

import datetime
import pathlib
from dataclasses import dataclass, field

from hunterx.architecture import cycles as cycles_module
from hunterx.architecture import docs as docs_module
from hunterx.architecture import imports as imports_module
from hunterx.architecture import stability as stability_module
from hunterx.architecture.layers import ROOT_LAYER, resolve_layer
from hunterx.architecture.policy import Policy, default_policy, load_policy
from hunterx.architecture.report import ArchitectureReport
from hunterx.architecture.violations import Severity, Violation, ViolationCodes


@dataclass(slots=True)
class LintOptions:
    """Configuration for a lint run.

    Attributes:
        repo_root: repository root (where ``pyproject.toml`` lives).
        package_root: relative path to the package root under ``repo_root``.
        check_package: scan the ``hunterx`` package.
        check_plugins: scan the top-level ``plugins/`` directory.
        check_tools: scan the top-level ``tools/`` directory.
        check_docs: run documentation validation.
        check_stability: compare the API against the baseline.
        check_cycles: run circular dependency detection.
        fail_on_warnings: treat warnings as failures.

    """

    repo_root: pathlib.Path = field(default_factory=pathlib.Path.cwd)
    package_root: str = "src"
    check_package: bool = True
    check_plugins: bool = True
    check_tools: bool = True
    check_docs: bool = True
    check_stability: bool = True
    check_cycles: bool = True
    fail_on_warnings: bool = False


class ArchitectureLinter:
    """Validate a repository against the HunterX architecture policy."""

    def __init__(
        self,
        policy: Policy | None = None,
        options: LintOptions | None = None,
    ) -> None:
        """Initialize the linter.

        Args:
            policy: the policy to enforce; defaults to the built-in matrix.
            options: scan options; defaults are used when omitted.

        """
        self.policy = policy or default_policy()
        self.options = options or LintOptions()
        self.root = self.options.repo_root.resolve()
        self.package_path = self.root / self.options.package_root

    # ------------------------------------------------------------------
    # scanning
    # ------------------------------------------------------------------
    def _package_modules(self) -> dict[str, pathlib.Path]:
        """Map dotted module names to file paths under the package root."""
        modules: dict[str, pathlib.Path] = {}
        if not self.options.check_package or not self.package_path.is_dir():
            return modules
        for path in sorted(self.package_path.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            modules[imports_module.module_name_for(path, self.package_path)] = path
        return modules

    def _scan_imports(self, modules: dict[str, pathlib.Path]) -> dict[str, list]:
        """Extract import records for every module path."""
        records: dict[str, list] = {}
        for module, path in modules.items():
            module_records = imports_module.scan_file(path, module)
            if module_records:
                records[module] = module_records
        return records

    def _boundary_modules(self, directory_name: str) -> dict[str, pathlib.Path]:
        """Map modules under a top-level boundary directory (plugins/ or tools/)."""
        modules: dict[str, pathlib.Path] = {}
        base = self.root / directory_name
        if not base.is_dir():
            return modules
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            parts = list(path.relative_to(self.root).parts)
            parts[-1] = parts[-1][: -len(".py")] if parts[-1].endswith(".py") else parts[-1]
            module = ".".join(parts)
            modules[module] = path
        return modules

    # ------------------------------------------------------------------
    # validators
    # ------------------------------------------------------------------
    def _validate_import_rules(
        self,
        import_records: dict[str, list],
        violations: list[Violation],
    ) -> None:
        """Validate every internal import against the dependency matrix."""
        for source, records in sorted(import_records.items()):
            source_layer = resolve_layer(source)
            if source_layer.name == ROOT_LAYER:
                continue
            for record in records:
                target = record.target
                if target == "hunterx" or target.startswith("hunterx."):
                    self._check_internal_edge(source, source_layer.name, record, violations)
                elif self._is_blocked(target):
                    violations.append(
                        Violation(
                            code=ViolationCodes.IMPORT_FORBIDDEN,
                            severity=Severity.ERROR,
                            message=f"Module '{source}' imports forbidden target '{target}'.",
                            remediation=(
                                "Shipping code must never import legacy roots (core/, "
                                "the flat hunterx/ package, scripts/) or private "
                                "packages."
                            ),
                            module=source,
                            line=record.line,
                            target=target,
                        )
                    )

    def _is_blocked(self, target: str) -> bool:
        """Return ``True`` when a target prefix is blocked by policy."""
        for prefix in self.policy.blocked_prefixes:
            if target == prefix or target.startswith(prefix):
                return True
        return any(
            self._matches_pattern(rule.target_pattern, target)
            for rule in self.policy.forbidden_imports
        )

    @staticmethod
    def _matches_pattern(pattern: str, value: str) -> bool:
        """Match a dotted prefix pattern against a module name."""
        if pattern.endswith(".*"):
            prefix = pattern[:-2]
            return value == prefix or value.startswith(f"{prefix}.")
        return value == pattern or value.startswith(f"{pattern}.")

    def _check_internal_edge(
        self,
        source: str,
        source_layer: str,
        record: object,
        violations: list[Violation],
    ) -> None:
        """Validate a single hunterx-internal import edge."""
        target = record.target
        target_layer = resolve_layer(target).name
        if source_layer == target_layer:
            return
        if source_layer == "platform":
            return
        if target_layer == ROOT_LAYER:
            return
        if self.policy.is_allowed(source_layer, target_layer):
            return
        if self.policy.is_conditional(source, target) is not None:
            return
        violations.append(
            Violation(
                code=ViolationCodes.IMPORT_LAYER,
                severity=Severity.ERROR,
                message=(
                    f"Layer boundary violation: '{source}' ({source_layer}) imports "
                    f"'{target}' ({target_layer}), which is not in the approved "
                    f"dependency matrix for {source_layer}."
                ),
                remediation=(
                    "Dependencies must point inward. Move the shared logic into the "
                    "owning layer, publish it as a domain port, or emit an event "
                    "instead of importing the target layer."
                ),
                module=source,
                line=getattr(record, "line", 0),
                target=target,
                details={"source_layer": source_layer, "target_layer": target_layer},
            )
        )

    def _validate_boundary(
        self,
        modules: dict[str, pathlib.Path],
        code: str,
        message_prefix: str,
        allowed_prefixes: tuple[str, ...],
        violations: list[Violation],
    ) -> None:
        """Validate that boundary modules import only approved hunterx packages."""
        for module, path in sorted(modules.items()):
            for record in imports_module.scan_file(path, module):
                target = record.target
                if not (target == "hunterx" or target.startswith("hunterx.")):
                    continue
                if target == "hunterx":
                    continue
                if any(target == prefix or target.startswith(f"{prefix}.") for prefix in allowed_prefixes):
                    continue
                violations.append(
                    Violation(
                        code=code,
                        severity=Severity.ERROR,
                        message=f"{message_prefix} '{module}' imports '{target}' outside the approved surface.",
                        remediation=(
                            f"Allowed imports are: {', '.join(allowed_prefixes)}. "
                            "Communicate through the SDK/domain contracts only."
                        ),
                        module=module,
                        line=record.line,
                        target=target,
                    )
                )

    # ------------------------------------------------------------------
    # cycles
    # ------------------------------------------------------------------
    def _validate_cycles(
        self,
        import_records: dict[str, list],
        violations: list[Violation],
        report: ArchitectureReport,
    ) -> None:
        """Detect circular dependencies and separate known cycles."""
        detected = cycles_module.find_cycles(import_records, package="hunterx")
        for cycle in detected:
            known = self.policy.find_known_cycle(cycle.modules)
            if known is not None:
                report.known_cycles.append(list(cycle.modules))
                continue
            violations.append(
                Violation(
                    code=ViolationCodes.CIRCULAR_DEPENDENCY,
                    severity=Severity.ERROR,
                    message=(
                        f"Circular dependency detected between modules: "
                        f"{', '.join(cycle.modules)}."
                    ),
                    remediation=(
                        "Break the cycle by extracting the shared dependency into a "
                        "lower layer. Use `if TYPE_CHECKING:` only for type-only "
                        "references."
                    ),
                    module=cycle.modules[0],
                    details={"cycle": list(cycle.modules)},
                )
            )
            report.cycles.append(list(cycle.modules))

    # ------------------------------------------------------------------
    # stability
    # ------------------------------------------------------------------
    def _validate_stability(
        self,
        modules: dict[str, pathlib.Path],
        violations: list[Violation],
    ) -> None:
        """Compare the current public API against the committed baseline."""
        baseline_path = self.root / self.policy.api_baseline
        if not baseline_path.is_file():
            return
        baseline = stability_module.load_baseline(baseline_path)
        current = stability_module.snapshot_tree(self.package_path)
        for change in stability_module.compare_api(baseline, current):
            if not change.breaking:
                continue
            code = (
                ViolationCodes.API_SIGNATURE if change.kind == "signature" else ViolationCodes.API_BREAKING
            )
            violations.append(
                Violation(
                    code=code,
                    severity=Severity.ERROR,
                    message=(
                        f"Breaking API change in '{change.module}': public name "
                        f"'{change.name}' {change.detail}."
                    ),
                    remediation=(
                        "Restore the removed name or update the committed baseline "
                        "(config/api_baseline.json) with "
                        "`hunterx-arch stability --generate` after recording the "
                        "intentional change in CHANGELOG.md."
                    ),
                    module=change.module,
                    target=change.name,
                    details={"kind": change.kind},
                )
            )

    # ------------------------------------------------------------------
    # waivers
    # ------------------------------------------------------------------
    def _apply_waivers(self, violations: list[Violation]) -> list[Violation]:
        """Move waived violations into known issues (unless expired)."""
        kept: list[Violation] = []
        for violation in violations:
            waiver = self.policy.find_waiver(violation.module, violation.target, violation.code)
            if waiver is None:
                kept.append(violation)
                continue
            if waiver.expires and self._is_expired(waiver.expires):
                kept.append(
                    Violation(
                        code=ViolationCodes.WAIVER_EXPIRED,
                        severity=Severity.ERROR,
                        message=(
                            f"Waiver {waiver.id} for '{violation.module}' expired on "
                            f"{waiver.expires}; the violation is active again."
                        ),
                        remediation=(
                            "Resolve the architectural debt and remove the waiver from "
                            "config/architecture.yaml."
                        ),
                        module=violation.module,
                        line=violation.line,
                        target=violation.target,
                    )
                )
                continue
            violation.severity = Severity.INFO
            violation.code = ViolationCodes.WAIVED_ISSUE
            self._waived.append(violation)
        return kept

    @staticmethod
    def _is_expired(iso_date: str) -> bool:
        """Return ``True`` when an ISO date is in the past."""
        try:
            expiry = datetime.date.fromisoformat(iso_date)
        except ValueError:
            return False
        return expiry < datetime.date.today()

    # ------------------------------------------------------------------
    # main entry
    # ------------------------------------------------------------------
    def run(self) -> ArchitectureReport:
        """Run every enabled check and return the aggregated report."""
        self._waived: list[Violation] = []
        modules = self._package_modules()
        import_records = self._scan_imports(modules)
        violations: list[Violation] = []
        report = ArchitectureReport(
            module_count=len(modules),
            source_line_count=sum(_line_count(path) for path in modules.values()),
            layer_graph=cycles_module.build_layer_graph(import_records),
        )

        if self.options.check_cycles:
            self._validate_cycles(import_records, violations, report)

        self._validate_import_rules(import_records, violations)

        if self.options.check_plugins:
            plugin_modules = self._boundary_modules("plugins")
            self._validate_boundary(
                plugin_modules,
                ViolationCodes.PLUGIN_BOUNDARY,
                "Plugin boundary violation:",
                self.policy.plugin_boundary,
                violations,
            )
        if self.options.check_tools:
            tool_modules = self._boundary_modules("tools")
            self._validate_boundary(
                tool_modules,
                ViolationCodes.TOOL_BOUNDARY,
                "Tool boundary violation:",
                self.policy.tool_boundary,
                violations,
            )

        if self.options.check_docs:
            violations.extend(docs_module.validate_documentation(modules, self.policy.doc_requirements))

        if self.options.check_stability:
            self._validate_stability(modules, violations)

        report.violations = self._apply_waivers(violations)
        report.known_issues = self._waived
        return report


def _line_count(path: pathlib.Path) -> int:
    """Count non-empty source lines in a file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip())


def run_lint(
    options: LintOptions | None = None,
    *,
    policy: Policy | None = None,
) -> ArchitectureReport:
    """Load the policy and run the linter.

    Args:
        options: scan options; the policy is loaded from
            ``config/architecture.yaml`` when present.
        policy: an explicit policy; when omitted the policy is loaded from
            ``<root>/config/architecture.yaml`` (or the built-in default).

    Returns:
        The aggregated :class:`ArchitectureReport`.

    """
    root = (options.repo_root if options else pathlib.Path.cwd()).resolve()
    if policy is None:
        policy = load_policy(root / "config" / "architecture.yaml")
    return ArchitectureLinter(policy=policy, options=options).run()
