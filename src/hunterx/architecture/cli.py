# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Command-line interface for the architecture enforcement framework.

Provides the ``hunterx-arch`` console script and ``python -m
hunterx.architecture`` entry point.

Commands:

- ``lint`` — run all architecture checks; exit 1 on violations.
- ``report`` — write a Markdown/JSON architecture report to a file.
- ``graph`` — write a Mermaid dependency graph to a file (or stdout).
- ``matrix`` — print the dependency matrix.
- ``stability`` — compare the public API against the committed baseline, or
  regenerate the baseline with ``--generate``.

Developer experience is a first-class requirement: every violation message
carries remediation guidance, and ``--verbose`` prints it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Sequence

from hunterx.architecture import __version__
from hunterx.architecture.lint import LintOptions, run_lint
from hunterx.architecture.policy import find_repo_root, load_policy
from hunterx.architecture.report import ArchitectureReport
from hunterx.architecture.stability import load_baseline, save_baseline, snapshot_tree

_EXIT_OK = 0
_EXIT_VIOLATIONS = 1
_EXIT_ERROR = 2


def _common_parser() -> argparse.ArgumentParser:
    """Parser holding options shared by the main and sub parsers."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=None,
        help="Repository root (default: discovered by walking up from CWD).",
    )
    parser.add_argument(
        "--policy",
        type=pathlib.Path,
        default=None,
        help="Path to architecture.yaml (default: <root>/config/architecture.yaml).",
    )
    return parser


def _build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="hunterx-arch",
        description="HunterX Architecture Enforcement Framework.",
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"hunterx-arch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    lint = sub.add_parser("lint", parents=[common], help="Run architecture checks (exit 1 on violations).")
    lint.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format.",
    )
    lint.add_argument("--no-docs", action="store_true", help="Skip documentation validation.")
    lint.add_argument("--no-stability", action="store_true", help="Skip API stability checks.")
    lint.add_argument("--no-cycles", action="store_true", help="Skip cycle detection.")
    lint.add_argument("--fail-on-warnings", action="store_true", help="Fail on warnings too.")
    lint.add_argument("--verbose", action="store_true", help="Print remediation guidance.")

    report = sub.add_parser("report", parents=[common], help="Write a full architecture report to a file.")
    report.add_argument("--format", choices=("markdown", "json", "text"), default="markdown")
    report.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output file (default: architecture-report.md in the repo root).",
    )

    graph = sub.add_parser("graph", parents=[common], help="Emit the layer dependency graph as Mermaid.")
    graph.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="Output file (default: stdout).",
    )

    matrix = sub.add_parser("matrix", parents=[common], help="Print the dependency matrix.")
    matrix.add_argument("--format", choices=("text", "yaml", "json"), default="text")

    stability = sub.add_parser("stability", parents=[common], help="Check or regenerate the API baseline.")
    stability.add_argument("--generate", action="store_true", help="Regenerate the baseline file.")
    stability.add_argument("--output", type=pathlib.Path, default=None, help="Baseline file path.")

    return parser


def _resolve_args(args: argparse.Namespace) -> tuple[pathlib.Path, pathlib.Path | None]:
    """Resolve the repo root and policy path from CLI arguments."""
    root = args.root.resolve() if args.root else find_repo_root()
    return root, args.policy


def _print_violations(report: ArchitectureReport, *, verbose: bool) -> None:
    """Print violations to stderr with optional remediation guidance."""
    if not report.violations:
        return
    for violation in report.violations:
        location = f"{violation.module}:{violation.line}" if violation.module else "-"
        line = f"[{violation.severity}] {violation.code} {location}: {violation.message}"
        print(line, file=sys.stderr)
        if verbose:
            print(f"    fix: {violation.remediation}", file=sys.stderr)


def _exit_code(report: ArchitectureReport, options: LintOptions) -> int:
    """Map a report to a process exit code."""
    if report.error_count() > 0:
        return _EXIT_VIOLATIONS
    if options.fail_on_warnings and report.warning_count() > 0:
        return _EXIT_VIOLATIONS
    return _EXIT_OK


def _cmd_lint(args: argparse.Namespace, root: pathlib.Path, policy_path: pathlib.Path | None) -> int:
    """Handle the ``lint`` subcommand."""
    options = LintOptions(
        repo_root=root,
        check_docs=not args.no_docs,
        check_stability=not args.no_stability,
        check_cycles=not args.no_cycles,
        fail_on_warnings=args.fail_on_warnings,
    )
    report = run_lint(options, policy=load_policy(policy_path))
    if args.format == "json":
        print(report.to_json())
    elif args.format == "markdown":
        print(report.to_markdown())
    else:
        print(report.to_text())
    _print_violations(report, verbose=args.verbose)
    return _exit_code(report, options)


def _cmd_report(args: argparse.Namespace, root: pathlib.Path) -> int:
    """Handle the ``report`` subcommand."""
    report = run_lint(LintOptions(repo_root=root))
    output = args.output or (root / "architecture-report.md")
    if args.format == "json":
        content = report.to_json()
    elif args.format == "text":
        content = report.to_text()
    else:
        content = report.to_markdown()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content + "\n", encoding="utf-8")
    print(f"Architecture report written to {output}")
    return _exit_code(report, LintOptions(repo_root=root))


def _cmd_graph(args: argparse.Namespace, root: pathlib.Path) -> int:
    """Handle the ``graph`` subcommand."""
    report = run_lint(LintOptions(repo_root=root, check_docs=False, check_stability=False))
    mermaid = report.render_mermaid()
    if args.output is not None:
        args.output.write_text(mermaid + "\n", encoding="utf-8")
        print(f"Layer graph written to {args.output}")
    else:
        print(mermaid)
    return _EXIT_OK


def _cmd_matrix(args: argparse.Namespace, root: pathlib.Path, policy_path: pathlib.Path | None) -> int:
    """Handle the ``matrix`` subcommand."""
    policy = load_policy(policy_path)
    rows: list[dict[str, object]] = []
    for source in sorted(policy.allowed):
        rows.append({"layer": source, "allowed": sorted(policy.allowed[source])})
    if args.format == "json":
        print(json.dumps(rows, indent=2))
    elif args.format == "yaml":
        import yaml

        print(yaml.safe_dump({"layers": {row["layer"]: row["allowed"] for row in rows}}, sort_keys=False))
    else:
        width = max(len(str(row["layer"])) for row in rows)
        print(f"{'layer':<{width}}  allowed")
        for row in rows:
            print(f"{row['layer']:<{width}}  {', '.join(str(a) for a in row['allowed'])}")
    return _EXIT_OK


def _cmd_stability(args: argparse.Namespace, root: pathlib.Path) -> int:
    """Handle the ``stability`` subcommand."""
    policy = load_policy(root / "config" / "architecture.yaml")
    baseline_path = args.output or (root / policy.api_baseline)
    if args.generate:
        snapshot = snapshot_tree(root / policy.package_root)
        save_baseline(baseline_path, snapshot)
        print(f"API baseline written to {baseline_path}")
        return _EXIT_OK
    if not baseline_path.is_file():
        print(
            f"No API baseline found at {baseline_path}. Generate one with "
            "`hunterx-arch stability --generate`.",
            file=sys.stderr,
        )
        return _EXIT_ERROR
    from hunterx.architecture.stability import compare_api

    baseline = load_baseline(baseline_path)
    current = snapshot_tree(root / policy.package_root)
    changes = compare_api(baseline, current)
    breaking = [change for change in changes if change.breaking]
    for change in changes:
        marker = "BREAKING" if change.breaking else "changed"
        print(f"[{marker}] {change.module} {change.name}: {change.detail}")
    print(f"\n{len(breaking)} breaking change(s), {len(changes) - len(breaking)} non-breaking change(s).")
    return _EXIT_VIOLATIONS if breaking else _EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Console script entry point.

    Args:
        argv: arguments; defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code.

    """
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else sys.argv[1:])
    try:
        root, policy_path = _resolve_args(args)
        if args.command == "lint":
            return _cmd_lint(args, root, policy_path)
        if args.command == "report":
            return _cmd_report(args, root)
        if args.command == "graph":
            return _cmd_graph(args, root)
        if args.command == "matrix":
            return _cmd_matrix(args, root, policy_path)
        if args.command == "stability":
            return _cmd_stability(args, root)
        parser.error(f"Unknown command '{args.command}'.")
        return _EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"hunterx-arch: {exc}", file=sys.stderr)
        return _EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
