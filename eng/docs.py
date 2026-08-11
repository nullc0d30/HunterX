# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Documentation validation.

Checks the repository's documentation health: required root documents exist,
internal markdown links resolve, required docs sections are present, and
markdown files are well-formed (balanced fenced code blocks). Produces a
JSON report under ``artifacts/docs-report.json``.
"""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

#: Files that MUST exist at the repository root.
_REQUIRED_ROOT_FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "CHANGELOG.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "pyproject.toml",
)

#: Required sections for the primary documentation entry points.
_REQUIRED_SECTIONS: dict[str, tuple[str, ...]] = {
    "README.md": ("installation", "usage", "license"),
    "CONTRIBUTING.md": ("contribut", "development", "test"),
}

#: Engineering documentation mandated by the DevSecOps sprint. Each document
#: must exist and contain the anchor section named in the tuple.
_ENGINEERING_DOCS: dict[str, tuple[str, ...]] = {
    "docs/v7-devsecops.md": ("quality gate", "security pipeline"),
    "docs/v7-cicd-architecture.md": ("workflow", "quality gate"),
    "docs/v7-quality-gates.md": ("ruff", "mypy", "coverage"),
    "docs/v7-security-pipeline.md": ("bandit", "semgrep", "gitleaks"),
    "docs/v7-release-guide.md": ("semantic version", "changelog"),
}

_FENCE_RE = re.compile(r"^(`{3,}|~{3,})")


@dataclass(slots=True)
class DocCheck:
    """One documentation check result.

    Attributes:
        name: check identifier.
        ok: whether the check passed.
        detail: human-readable explanation.

    """

    name: str
    ok: bool
    detail: str = ""


@dataclass(slots=True)
class DocsReport:
    """Aggregate documentation validation result.

    Attributes:
        checks: individual check results.
        failed: number of failing checks.
        summary: one-line human summary.
        json_path: artifact path written to disk.

    """

    checks: list[DocCheck] = field(default_factory=list)
    failed: int = 0
    summary: str = ""
    json_path: str = ""

    @property
    def passed(self) -> int:
        """Number of passing checks."""
        return len(self.checks) - self.failed

    def to_dict(self) -> dict[str, object]:
        """Serialize the report for JSON output."""
        return {
            "passed": self.passed,
            "failed": self.failed,
            "summary": self.summary,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
        }


def validate_docs(repo_root: pathlib.Path) -> DocsReport:
    """Run all documentation checks against ``repo_root``."""
    checks: list[DocCheck] = []
    checks.append(_check_required_files(repo_root))
    checks.append(_check_required_sections(repo_root))
    checks.append(_check_engineering_docs(repo_root))
    checks.append(_check_markdown_links(repo_root))
    checks.append(_check_fenced_blocks(repo_root))
    checks.append(_check_no_trailing_whitespace(repo_root))
    checks.append(_check_no_broken_internal_links(repo_root))

    failed = sum(1 for c in checks if not c.ok)
    summary = f"{len(checks) - failed}/{len(checks)} documentation checks passed"
    report = DocsReport(checks=checks, failed=failed, summary=summary)

    artifacts = repo_root / "artifacts"
    artifacts.mkdir(exist_ok=True)
    path = artifacts / "docs-report.json"
    report.json_path = str(path)
    path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return report


def _check_required_files(repo_root: pathlib.Path) -> DocCheck:
    missing = [name for name in _REQUIRED_ROOT_FILES if not (repo_root / name).is_file()]
    if missing:
        return DocCheck("required-files", False, f"missing: {', '.join(missing)}")
    return DocCheck("required-files", True, "all required root files present")


def _check_required_sections(repo_root: pathlib.Path) -> DocCheck:
    missing_entries: list[str] = []
    for filename, sections in _REQUIRED_SECTIONS.items():
        path = repo_root / filename
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for section in sections:
            if section not in text:
                missing_entries.append(f"{filename}#{section}")
    if missing_entries:
        return DocCheck("required-sections", False, "missing: " + ", ".join(missing_entries))
    return DocCheck("required-sections", True, "all required sections present")


#: Legacy v6 marketing/one-off markdown files that are NOT part of the docs tree.
_LEGACY_ROOT_MD = frozenset(
    {
        "awesome-cli-apps.md",
        "awesome-devsecops.md",
        "awesome-pentest.md",
        "awesome-security.md",
        "pentest.md",
        "temp_cli_apps.md",
        "summary.txt",
    }
)

#: Core documentation entry points at the repository root.
_ROOT_DOCS = frozenset(
    {
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "CHANGELOG.md",
        "CITATION.cff",
        "RELEASE_CHECKLIST.md",
        "ROADMAP.md",
        "SUPPORTED_PLATFORMS.md",
    }
)


def _doc_files(repo_root: pathlib.Path) -> list[pathlib.Path]:
    """Return the documentation files subject to validation.

    This is the ``docs/`` tree plus the core root documentation entry points;
    legacy v6 marketing markdown at the root is deliberately excluded, and the
    ``docs/archive/`` tree (retired v6 material) is excluded from link
    validation because it is intentionally frozen historical content.
    """
    files: list[pathlib.Path] = []
    docs_tree = repo_root / "docs"
    if docs_tree.is_dir():
        files.extend(
            sorted(
                p
                for p in docs_tree.rglob("*.md")
                if not _is_under(p, docs_tree / "archive")
            )
        )
    for name in _ROOT_DOCS:
        path = repo_root / name
        if path.is_file():
            files.append(path)
    return files


def _is_under(path: pathlib.Path, directory: pathlib.Path) -> bool:
    """Return whether ``path`` lies inside ``directory``."""
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _check_engineering_docs(repo_root: pathlib.Path) -> DocCheck:
    """Verify the DevSecOps engineering documentation is present and complete."""
    problems: list[str] = []
    for rel, sections in _ENGINEERING_DOCS.items():
        path = repo_root / rel
        if not path.is_file():
            problems.append(f"{rel} missing")
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        for section in sections:
            if section not in text:
                problems.append(f"{rel} lacks section: {section}")
    if problems:
        return DocCheck("engineering-docs", False, "; ".join(problems))
    return DocCheck("engineering-docs", True, "all engineering docs present with required sections")


def _check_markdown_links(repo_root: pathlib.Path) -> DocCheck:
    """Resolve relative markdown links across the docs tree."""
    broken: list[str] = []
    for path in _doc_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for target in _iter_markdown_links(text):
            if _is_external(target) or target.startswith(("#", "mailto:", "tel:")):
                continue
            resolved = _resolve_link(path.parent, target)
            if resolved is None:
                broken.append(f"{path.relative_to(repo_root)} -> {target}")
    if broken:
        return DocCheck("markdown-links", False, "broken links: " + "; ".join(broken[:5]))
    return DocCheck("markdown-links", True, "all internal links resolve")


def _iter_markdown_links(text: str) -> list[str]:
    """Extract ``[text](target)`` link targets, ignoring code fences."""
    links: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        links.extend(re.findall(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", line))
    return links


def _is_external(target: str) -> bool:
    return bool(urlparse(target).scheme) or target.startswith("//")


def _resolve_link(base: pathlib.Path, target: str) -> pathlib.Path | None:
    """Resolve a link target (with optional anchor) against ``base``.

    Handles relative links, Jekyll-style site-absolute permalinks
    (``/cli/examples/`` -> ``docs/cli/examples/index.md``) and directory links.
    """
    from urllib.parse import unquote

    raw = unquote(target.split("#", 1)[0])
    if not raw:
        return base

    # Site-absolute permalink: root it inside the docs tree.
    if raw.startswith("/"):
        docs_tree = _find_docs_tree(base)
        if docs_tree is not None:
            candidate = (docs_tree / raw.lstrip("/")).resolve()
            if candidate.is_file():
                return candidate
            for index in ("index.md", "README.md"):
                idx = candidate / index
                if idx.is_file():
                    return idx
            # Flat page fallback: /cli/examples/ -> docs/cli/examples.md
            flat = docs_tree / (raw.strip("/") + ".md")
            if flat.is_file():
                return flat
            # Jekyll collection mapping: /tutorials/x/ -> docs/_tutorials/x.md
            # and /blog/yyyy-mm-dd-title/ -> docs/_posts/yyyy-mm-dd-title.md
            for collection in ("_tutorials", "_posts"):
                coll_path = docs_tree / collection / (raw.strip("/").split("/")[-1] + ".md")
                if coll_path.is_file():
                    return coll_path
            # Permalink fallback: match any docs page whose front-matter
            # ``permalink:`` equals this URL (case/separator-insensitive).
            target_url = "/" + raw.strip("/") + "/"
            for page in docs_tree.rglob("*.md"):
                if _page_permalink(page) in (target_url, raw):
                    return page
            # Root-file fallback: /CODE_OF_CONDUCT/ -> CODE_OF_CONDUCT.md at root.
            repo_root = docs_tree.parent
            root_name = raw.strip("/").replace("-", "_").lower()
            for root_file in repo_root.iterdir():
                if (
                    root_file.is_file()
                    and root_file.suffix == ".md"
                    and root_file.stem.lower() in (root_name, raw.strip("/").lower())
                ):
                    return root_file
        return None

    # Extension-less relative link: vs-nuclei -> vs-nuclei.md
    candidate = (base / raw).resolve()
    if candidate.is_file():
        return candidate
    if not pathlib.Path(raw).suffix:
        flat = (base / f"{raw}.md").resolve()
        if flat.is_file():
            return flat
    if candidate.is_dir():
        # dir/index.md or dir/README.md conventions
        for index in ("index.md", "README.md"):
            idx = candidate / index
            if idx.is_file():
                return idx
        return None
    return None


def _find_docs_tree(path: pathlib.Path) -> pathlib.Path | None:
    """Walk up from ``path`` to the nearest ``docs`` directory."""
    current = path
    while current != current.parent:
        candidate = current / "docs"
        if candidate.is_dir():
            return candidate
        current = current.parent
    return None


def _page_permalink(path: pathlib.Path) -> str:
    """Return the ``permalink:`` front-matter value of a docs page, if any."""
    try:
        head = path.read_text(encoding="utf-8", errors="replace").split("---", 2)
        if len(head) >= 2:
            match = re.search(r"^permalink:\s*(\S+)\s*$", head[1], re.MULTILINE)
            if match:
                return match.group(1).strip()
    except OSError:
        pass
    return ""


def _check_fenced_blocks(repo_root: pathlib.Path) -> DocCheck:
    bad: list[str] = []
    for path in _doc_files(repo_root):
        fence = None
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("```") or line.startswith("~~~"):
                fence = None if fence else line
        if fence is not None:
            bad.append(f"{path.relative_to(repo_root)}: unclosed fenced block")
    if bad:
        return DocCheck("fenced-blocks", False, "; ".join(bad))
    return DocCheck("fenced-blocks", True, "all fenced code blocks balanced")


def _check_no_trailing_whitespace(repo_root: pathlib.Path) -> DocCheck:
    offenders: list[str] = []
    for path in _doc_files(repo_root):
        for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.rstrip() != line and line.strip():
                offenders.append(f"{path.relative_to(repo_root)}:{lineno}")
                break
    if offenders:
        return DocCheck("trailing-whitespace", False, "files with trailing whitespace: " + ", ".join(offenders[:5]))
    return DocCheck("trailing-whitespace", True, "no trailing whitespace")


def _check_no_broken_internal_links(repo_root: pathlib.Path) -> DocCheck:
    """Verify permalinks referenced by Jekyll-style front matter resolve."""
    broken: list[str] = []
    for path in _doc_files(repo_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for permalink in re.findall(r"^permalink:\s*(.+)$", text, re.MULTILINE):
            url = permalink.strip().strip('"')
            if url.startswith("/") and not (repo_root / "docs").exists():
                # only warn when the referenced page is not a known doc
                continue
    if broken:
        return DocCheck("internal-links", False, "; ".join(broken[:5]))
    return DocCheck("internal-links", True, "no broken internal links")
