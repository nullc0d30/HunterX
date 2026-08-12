# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Release engineering.

Semantic versioning helpers, changelog generation, release-note extraction,
artifact checksum generation/verification and a rollback compatibility check.
Pure logic (no network) so the release workflow is deterministic and testable.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
from dataclasses import dataclass

_SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$")


@dataclass(frozen=True, slots=True)
class Version:
    """A semantic version.

    Attributes:
        major: major component.
        minor: minor component.
        patch: patch component.
        pre: prerelease suffix (e.g. ``"rc.1"``).
        build: build metadata (ignored in precedence).

    """

    major: int
    minor: int
    patch: int
    pre: str = ""
    build: str = ""

    @property
    def is_prerelease(self) -> bool:
        """Return ``True`` when this version carries a prerelease suffix."""
        return bool(self.pre)

    def bump(self, part: str) -> Version:
        """Return a new version with ``part`` (major/minor/patch) bumped."""
        if part == "major":
            return Version(self.major + 1, 0, 0)
        if part == "minor":
            return Version(self.major, self.minor + 1, 0)
        if part == "patch":
            return Version(self.major, self.minor, self.patch + 1)
        raise ValueError(f"unknown bump target: {part}")

    def release(self) -> Version:
        """Return the release (non-prerelease) form of this version."""
        return Version(self.major, self.minor, self.patch)

    def __str__(self) -> str:
        out = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre:
            out += f"-{self.pre}"
        if self.build:
            out += f"+{self.build}"
        return out

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        left = (self.major, self.minor, self.patch, _pre_key(self.pre))
        right = (other.major, other.minor, other.patch, _pre_key(other.pre))
        return left < right

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self == other or self < other


def _pre_key(pre: str) -> tuple[int, tuple[tuple[int, str], ...]]:
    """Sort prereleases per SemVer rules (identifiers compare numerically first)."""
    if not pre:
        return (2, ())
    parts = pre.split(".")
    key_parts: list[tuple[int, str]] = []
    for part in parts:
        if part.isdigit():
            key_parts.append((0, str(int(part)).zfill(10)))
        else:
            key_parts.append((1, part))
    return (1, tuple(key_parts))


def parse_version(text: str) -> Version:
    """Parse a SemVer string, raising ``ValueError`` when invalid."""
    match = _SEMVER_RE.match(text.strip())
    if not match:
        raise ValueError(f"invalid semantic version: {text!r}")
    major, minor, patch, pre, build = match.groups()
    return Version(int(major), int(minor), int(patch), pre or "", build or "")


def is_valid_version(text: str) -> bool:
    """Return ``True`` when ``text`` is a valid semantic version string."""
    try:
        parse_version(text)
        return True
    except ValueError:
        return False


def suggest_bump(conventional_commits: list[str]) -> str:
    """Suggest the next version bump from a list of conventional commits.

    ``feat!`` / ``BREAKING CHANGE`` -> major; ``feat`` -> minor; anything else
    with changes -> patch; no changes -> ``"none"``.
    """
    breaking = any(re.search(r"^(feat|fix|refactor)!:", c) or "BREAKING CHANGE:" in c for c in conventional_commits)
    if breaking:
        return "major"
    if any(c.startswith("feat") for c in conventional_commits):
        return "minor"
    if any(
        c.startswith(("fix", "refactor", "perf", "docs", "test", "chore", "ci", "style", "build", "revert"))
        for c in conventional_commits
    ):
        return "patch"
    return "none"


# ---------------------------------------------------------------------------
# changelog
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class ChangelogEntry:
    """One version entry in the changelog.

    Attributes:
        version: version string.
        date: release date (ISO) or empty for unreleased.
        body: raw markdown body.

    """

    version: str
    date: str = ""
    body: str = ""


def parse_changelog(text: str) -> list[ChangelogEntry]:
    """Parse Keep-a-Changelog sections into entries."""
    entries: list[ChangelogEntry] = []
    current: ChangelogEntry | None = None
    for line in text.splitlines():
        match = re.match(r"^##\s+\[([^\]]+)\]\s*(?:[—\-]\s*(.*))?$", line)
        if match:
            if current:
                entries.append(current)
            current = ChangelogEntry(version=match.group(1), date=match.group(2) or "")
            continue
        if current is not None and line.strip():
            current.body += line + "\n"
    if current:
        entries.append(current)
    return entries


def render_release_notes(entries: list[ChangelogEntry], version: str) -> str:
    """Render release notes for ``version`` from changelog entries."""
    for entry in entries:
        if entry.version == version:
            body = entry.body.strip()
            if not body:
                return f"## {version}\n\nNo changes documented."
            return f"## {version}\n\n{body}"
    return f"## {version}\n\nRelease notes pending."


# ---------------------------------------------------------------------------
# artifact verification
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Checksum:
    """SHA-256 checksum of one artifact.

    Attributes:
        name: artifact file name.
        sha256: hex digest.

    """

    name: str
    sha256: str


def sha256_file(path: pathlib.Path) -> str:
    """Return the lowercase hex SHA-256 digest of a file."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_checksums(artifacts: list[pathlib.Path]) -> list[Checksum]:
    """Compute SHA-256 checksums for ``artifacts``."""
    return [Checksum(name=p.name, sha256=sha256_file(p)) for p in artifacts if p.is_file()]


def verify_checksums(artifacts_dir: pathlib.Path) -> list[Checksum]:
    """Verify a ``SHA256SUMS.txt`` file inside ``artifacts_dir``.

    Raises:
        FileNotFoundError: when the checksum file or an artifact is missing.

    """
    sums_path = artifacts_dir / "SHA256SUMS.txt"
    if not sums_path.is_file():
        raise FileNotFoundError(f"missing {sums_path}")
    verified: list[Checksum] = []
    for line in sums_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        artifact = artifacts_dir / name
        actual = sha256_file(artifact)
        if actual != digest.strip():
            raise ValueError(f"checksum mismatch for {name}")
        verified.append(Checksum(name=name, sha256=digest.strip()))
    return verified


# ---------------------------------------------------------------------------
# rollback / release-readiness
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class RollbackPlan:
    """A documented rollback strategy for a release.

    Attributes:
        previous_version: the version being rolled back to.
        image_tag: container image tag to redeploy.
        package_version: distribution version to pin.
        migration_notes: whether an interactive DB rollback is required.

    """

    previous_version: str
    image_tag: str = ""
    package_version: str = ""
    migration_notes: str = "no data migration in this release"

    def to_dict(self) -> dict[str, str]:
        """Serialize the rollback plan for JSON output."""
        return {
            "previous_version": self.previous_version,
            "image_tag": self.image_tag,
            "package_version": self.package_version,
            "migration_notes": self.migration_notes,
        }


def build_rollback_plan(current: Version, previous: Version | None = None) -> RollbackPlan:
    """Build a rollback plan relative to a previous release."""
    prev = (previous or current.bump("patch")).release()
    return RollbackPlan(
        previous_version=str(prev),
        image_tag=f"nullc0d30/hunterx:{prev}",
        package_version=f"hunterxsec=={prev}",
    )
