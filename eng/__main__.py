# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unified CLI for the engineering platform.

Invoked by GitHub Actions and developers:

- ``python -m eng gates [--json] [--blocking]`` — run quality gates.
- ``python -m eng security [--json]`` — run the security pipeline.
- ``python -m eng sbom [--format cyclonedx|spdx]`` — generate an SBOM.
- ``python -m eng compliance`` — license/attribution/hygiene checks.
- ``python -m eng packaging [--json]`` — validate wheel/sdist.
- ``python -m eng readiness [--json]`` — production-readiness assessment.
- ``python -m eng check-release <version> [--json]`` — release validation.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _print_json(obj: dict[str, object]) -> None:
    print(json.dumps(obj, indent=2))


def cmd_gates(args: argparse.Namespace) -> int:
    """Run the configured quality gates."""
    from eng.gates import GateRunner, GateSpec, load_gate_specs
    from eng.gates.checks import default_checks

    specs_path = REPO_ROOT / "eng" / "config" / "gates.yaml"
    specs = load_gate_specs(specs_path) if specs_path.is_file() else []
    if not specs:
        specs = [
            GateSpec(name=n)
            for n in ("ruff", "mypy", "pytest", "coverage", "architecture", "deadcode", "dependencies", "docs")
        ]
    if args.gate:
        requested = set(args.gate)
        specs = [s for s in specs if s.name in requested]
    runner = GateRunner(gates=specs, checks=default_checks(), repo_root=REPO_ROOT)
    try:
        report = runner.run_blocking() if args.blocking else runner.run()
    except Exception as exc:  # noqa: BLE001
        print(f"quality gates blocked: {exc}")
        return 1
    if args.json:
        _print_json(report.to_dict())
        out_dir = REPO_ROOT / "artifacts"
        out_dir.mkdir(exist_ok=True)
        (out_dir / "gates-report.json").write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    else:
        for result in report.results:
            print(f"[{result.status.value.upper():7}] {result.name:<14} {result.detail}")
        print(f"\n{report.passed} passed, {report.failed} failed, {report.errors} errored, {report.skipped} skipped")
    return 1 if report.blocked else 0


def cmd_security(args: argparse.Namespace) -> int:
    """Run the security scanner pipeline."""
    from eng.security import run_security_pipeline

    report = run_security_pipeline(REPO_ROOT)
    if args.json:
        _print_json(report.to_dict())
    else:
        for scan in report.scans:
            print(f"[{scan.status.upper():7}] {scan.name:<12} {scan.detail}  findings={scan.findings}")
        print(f"\n{report.summary}")
    return 1 if report.blocked else 0


def cmd_sbom(args: argparse.Namespace) -> int:
    """Generate a CycloneDX or SPDX SBOM."""
    from eng.supplychain import generate_sbom, generate_sbom_spdx

    if args.format == "spdx":
        path = generate_sbom_spdx(REPO_ROOT)
        print(f"SPDX SBOM written to {path.relative_to(REPO_ROOT)}")
        return 0
    result = generate_sbom(REPO_ROOT)
    print(f"SBOM written to {result.path} ({result.components} components)")
    return 0


def cmd_compliance(args: argparse.Namespace) -> int:
    """Run license, attribution and repository-hygiene checks."""
    from eng.gates import GateRunner, GateSpec
    from eng.gates.checks import compliance_gate, hygiene_gate

    runner = GateRunner(
        gates=[GateSpec(name="compliance"), GateSpec(name="hygiene")],
        checks={"compliance": compliance_gate, "hygiene": hygiene_gate},
        repo_root=REPO_ROOT,
    )
    report = runner.run()
    for result in report.results:
        print(f"[{result.status.value.upper():7}] {result.name:<12} {result.detail}")
    print(f"\n{report.passed} passed, {report.failed} failed, {report.errors} errored")
    return 1 if report.blocked else 0


def cmd_packaging(args: argparse.Namespace) -> int:
    """Build and validate the wheel/sdist."""
    from eng.packaging import validate_packaging

    report = validate_packaging(REPO_ROOT)
    if args.json:
        _print_json(report.to_dict())
    else:
        for check in report.checks:
            print(f"[{check.status.value.upper():7}] {check.name:<8} {check.detail}")
        print(f"\n{report.summary}")
    return 0 if report.ok else 1


def cmd_readiness(args: argparse.Namespace) -> int:
    """Run the production-readiness assessment."""
    from eng.readiness import assess_readiness

    assessment = assess_readiness(REPO_ROOT)
    if args.json:
        _print_json(assessment.to_dict())
    else:
        print("Production Readiness Assessment")
        for name, score in assessment.scores.items():
            print(f"  {name:<14} {score:>5.1f}/100")
        print(f"  {'overall':<14} {assessment.overall:>5.1f}/100")
        print(f"  ready={assessment.ready}")
        for debt in assessment.tech_debt:
            print(f"  - {debt}")
    return 0 if assessment.ready else 1


def cmd_release(args: argparse.Namespace) -> int:
    """Validate a semantic version and its rollback plan."""
    from eng.release import build_rollback_plan, is_valid_version, parse_version

    if not is_valid_version(args.version):
        print(f"invalid version: {args.version!r}")
        return 2
    version = parse_version(args.version)
    plan = build_rollback_plan(version)
    if args.json:
        _print_json({"version": str(version), "prerelease": version.is_prerelease, "rollback": plan.to_dict()})
    else:
        print(f"version {version} is a valid semantic version")
        print(f"rollback -> {plan.previous_version} ({plan.image_tag})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(prog="python -m eng", description="HunterX engineering platform")
    sub = parser.add_subparsers(dest="command", required=True)

    p_gates = sub.add_parser("gates", help="run quality gates")
    p_gates.add_argument("--json", action="store_true", help="emit JSON report")
    p_gates.add_argument("--blocking", action="store_true", help="exit 1 if any mandatory gate fails")
    p_gates.add_argument("--gate", action="append", help="run only the named gate(s)")

    p_sec = sub.add_parser("security", help="run the security pipeline")
    p_sec.add_argument("--json", action="store_true")

    p_sbom = sub.add_parser("sbom", help="generate SBOM (CycloneDX or SPDX)")
    p_sbom.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx", help="SBOM format")

    sub.add_parser("compliance", help="run license/attribution/hygiene checks")

    p_pkg = sub.add_parser("packaging", help="validate wheel/sdist")
    p_pkg.add_argument("--json", action="store_true")

    p_rdy = sub.add_parser("readiness", help="production-readiness assessment")
    p_rdy.add_argument("--json", action="store_true")

    p_rel = sub.add_parser("check-release", help="validate a release version")
    p_rel.add_argument("version", help="semantic version, e.g. 7.1.0")
    p_rel.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = {
        "gates": cmd_gates,
        "security": cmd_security,
        "sbom": cmd_sbom,
        "compliance": cmd_compliance,
        "packaging": cmd_packaging,
        "readiness": cmd_readiness,
        "check-release": cmd_release,
    }[args.command]
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
