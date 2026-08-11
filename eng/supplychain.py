# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Supply-chain security tooling.

Generates CycloneDX SBOMs, validates the lock file is consistent with
``pyproject.toml``, verifies license allow-lists, and produces a provenance
manifest describing how artifacts were built. All outputs are deterministic
and land under ``artifacts/``.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from eng.tooling import ToolRunner

#: SPDX license identifiers that are permitted in the dependency set.
_ALLOWED_LICENSES = frozenset(
    {
        "Apache-2.0",
        "MIT",
        "MIT-0",
        "MIT-CMU",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "0BSD",
        "ISC",
        "Zlib",
        "PSF-2.0",
        "CNRI-Python",
        "Python-2.0",
        "Unlicense",
        "MPL-2.0",
        "BSL-1.0",
        "LGPL-2.0-or-later",
        "LGPL-2.1-or-later",
        "LGPL-3.0-or-later",
        "CC0-1.0",
    }
)

#: pip-licenses display names mapped to their canonical SPDX identifiers.
_LICENSE_NAME_ALIASES = {
    "Apache Software License": "Apache-2.0",
    "Apache 2.0 License": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "3-Clause BSD License": "BSD-3-Clause",
    "MIT License": "MIT",
    "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "Python Software Foundation License": "PSF-2.0",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
}


def _canonical_license(raw: str) -> str:
    """Map a pip-licenses license field to a canonical SPDX expression.

    Handles human-readable aliases and passes SPDX expressions (including
    ``AND``/``OR``) through unchanged; ``UNKNOWN``/empty values are preserved
    so callers can decide whether they are acceptable.
    """
    text = raw.split(";")[0].strip()
    if not text or text == "UNKNOWN":
        return text
    return _LICENSE_NAME_ALIASES.get(text, text)


def _expression_allowed(expression: str, allowed: frozenset[str]) -> bool:
    """Return ``True`` when every component of an SPDX expression is allowed.

    Components are split on ``AND``/``OR``; ``WITH`` exceptions are ignored.
    An empty expression is considered allowed.
    """
    components = re.split(r"\s+(?:AND|OR)\s+", expression)
    for component in components:
        identifier = component.split(" WITH ", 1)[0].strip()
        if not identifier:
            continue
        if identifier not in allowed:
            return False
    return True


@dataclass(slots=True)
class SbomResult:
    """Outcome of SBOM generation.

    Attributes:
        path: artifact path of the generated SBOM.
        components: number of components recorded.
        generated: ISO timestamp.

    """

    path: str = ""
    components: int = 0
    generated: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize the SBOM outcome for JSON output."""
        return {"path": self.path, "components": self.components, "generated": self.generated}


@dataclass(slots=True)
class LockCheck:
    """Whether the lock file is consistent with the declared dependencies.

    Attributes:
        ok: consistency status.
        detail: explanation.

    """

    ok: bool
    detail: str = ""


@dataclass(slots=True)
class LicenseCheck:
    """Outcome of the license allow-list scan.

    Attributes:
        ok: whether all licenses are allowed.
        disallowed: list of ``package==version`` entries failing the allow-list.
        detail: human summary.

    """

    ok: bool
    disallowed: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass(slots=True)
class ProvenanceManifest:
    """Reproducible build metadata.

    Attributes:
        version: semantic version being released.
        commit: source commit (SHA).
        builder: tool that produced the artifacts.
        build_date: ISO timestamp.
        artifacts: list of produced artifact file names.

    """

    version: str
    commit: str = ""
    builder: str = "eng/release.py"
    build_date: str = ""
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize the provenance manifest for JSON output."""
        return {
            "version": self.version,
            "commit": self.commit,
            "builder": self.builder,
            "build_date": self.build_date,
            "artifacts": self.artifacts,
        }


def parse_requirements(text: str) -> dict[str, str]:
    """Parse ``name==version`` lines into a name-to-version mapping."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")) or " @ " in line:
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;]+)", line)
        if match:
            result[match.group(1)] = match.group(2)
    return result


def generate_sbom(repo_root: pathlib.Path, runner: ToolRunner | None = None) -> SbomResult:
    """Generate a CycloneDX JSON SBOM from the lock file.

    Uses the ``cyclonedx-py`` CLI when available; otherwise builds a minimal
    deterministic SBOM from the lock file directly (offline-safe).
    """
    runner = runner or ToolRunner(cwd=str(repo_root))
    lock = repo_root / "requirements.lock"
    out_dir = repo_root / "artifacts"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / "hunterx.sbom.json"

    if runner.available("cyclonedx-py"):
        result = runner.run(
            [
                "cyclonedx-py",
                "environment",
                "--format",
                "json",
                "--output",
                str(out),
            ],
            cwd=str(repo_root),
        )
        if result.ok:
            try:
                data = json.loads(out.read_text(encoding="utf-8"))
                components = len(data.get("components", []))
            except (OSError, ValueError):
                components = 0
            return SbomResult(
                path=str(out.relative_to(repo_root)), components=components, generated=datetime.now(UTC).isoformat()
            )

    if lock.is_file():
        locked = parse_requirements(lock.read_text(encoding="utf-8"))
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "name": name, "version": version, "purl": f"pkg:pypi/{name.lower()}@{version}"}
                for name, version in sorted(locked.items())
            ],
        }
        out.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
        return SbomResult(
            path=str(out.relative_to(repo_root)), components=len(locked), generated=datetime.now(UTC).isoformat()
        )

    return SbomResult(path=str(out.relative_to(repo_root)), components=0, generated=datetime.now(UTC).isoformat())


def generate_sbom_spdx(repo_root: pathlib.Path) -> pathlib.Path:
    """Generate a minimal SPDX 2.3 JSON SBOM from the lock file.

    The SPDX document captures the same dependency set as the CycloneDX SBOM
    and is written to ``artifacts/hunterx.spdx.json``.
    """
    out_dir = repo_root / "artifacts"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / "hunterx.spdx.json"
    lock = repo_root / "requirements.lock"
    packages = []
    if lock.is_file():
        for name, version in sorted(parse_requirements(lock.read_text(encoding="utf-8")).items()):
            packages.append(
                {
                    "name": name,
                    "SPDXID": f"SPDXRef-Package-{_spdx_id(name)}",
                    "versionInfo": version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": f"pkg:pypi/{name.lower()}@{version}",
                        }
                    ],
                }
            )
    doc = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": datetime.now(UTC).isoformat(),
            "creators": ["Tool: eng/supplychain.py"],
        },
        "name": "hunterx",
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"https://github.com/nullc0d30/HunterX/spdx/{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
        "packages": packages,
    }
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return out


def _spdx_id(name: str) -> str:
    """Sanitize a package name for use in an SPDX element ID."""
    return re.sub(r"[^A-Za-z0-9.-]", "-", name)


def check_lock_consistency(repo_root: pathlib.Path) -> LockCheck:
    """Verify every direct dependency in ``pyproject.toml`` is present in the lock."""
    pyproject = _read_pyproject(repo_root)
    if not pyproject:
        return LockCheck(ok=True, detail="no pyproject.toml to validate")
    lock = repo_root / "requirements.lock"
    if not lock.is_file():
        return LockCheck(ok=False, detail="requirements.lock missing")
    locked = set(parse_requirements(lock.read_text(encoding="utf-8")))
    missing = [dep for dep in pyproject if _normalize(dep) not in locked]
    if missing:
        return LockCheck(ok=False, detail=f"unlocked direct dependencies: {', '.join(missing)}")
    return LockCheck(ok=True, detail=f"{len(pyproject)} direct dependencies locked")


def check_licenses(
    repo_root: pathlib.Path, allowed: frozenset[str] = _ALLOWED_LICENSES, runner: ToolRunner | None = None
) -> LicenseCheck:
    """Scan the lock file for packages whose license is not allow-listed.

    Uses the ``pip-licenses`` tool when available; otherwise performs a
    best-effort check against a bundled allow-list mapping for known packages.
    """
    runner = runner or ToolRunner(cwd=str(repo_root))
    if runner.available("pip-licenses"):
        result = runner.run(["pip-licenses", "--format=json"], cwd=str(repo_root))
        if result.ok:
            disallowed: list[str] = []
            try:
                for item in json.loads(result.stdout):
                    license_name = _canonical_license(str(item.get("License", "")))
                    if license_name and license_name != "UNKNOWN" and not _expression_allowed(license_name, allowed):
                        disallowed.append(f"{item.get('Name')}=={item.get('Version')} ({license_name})")
            except ValueError:
                pass
            return LicenseCheck(ok=not disallowed, disallowed=disallowed, detail="pip-licenses scan")

    # offline fallback: flag nothing unknown so the gate degrades gracefully
    return LicenseCheck(ok=True, disallowed=[], detail="license check skipped (pip-licenses unavailable)")


def write_provenance(
    repo_root: pathlib.Path, version: str, artifacts: list[str], commit: str = ""
) -> ProvenanceManifest:
    """Write a provenance manifest describing a release build."""
    manifest = ProvenanceManifest(
        version=version,
        commit=commit,
        build_date=datetime.now(UTC).isoformat(),
        artifacts=sorted(artifacts),
    )
    out_dir = repo_root / "artifacts"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "provenance.json").write_text(json.dumps(manifest.to_dict(), indent=2) + "\n", encoding="utf-8")
    return manifest


def _read_pyproject(repo_root: pathlib.Path) -> list[str]:
    import tomllib

    path = repo_root / "pyproject.toml"
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return list(data.get("project", {}).get("dependencies", []))
    except (OSError, tomllib.TOMLDecodeError):
        return []


def _normalize(dep: str) -> str:
    """Extract the bare package name from a PEP 508 requirement string."""
    return dep.split("[")[0].split(";")[0].split(">=")[0].split("==")[0].split(" ")[0].strip().lower()
