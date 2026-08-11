# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""JavaScript technology and dependency detection.

Detects frameworks, libraries, bundlers and runtime tooling from script content,
and extracts package dependencies from import/require statements and CDN
references. Detection is signature-based (regex) and pure; version extraction is
best-effort and never blocks a detection.

Everything here is **intelligence**: a detection asserts that a technology is
present in the bundle, not that a version is vulnerable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from hunterx.domain.javascript.analyzers import AnalyzeContext
from hunterx.domain.javascript.models import (
    JSDependency,
    JSEvidence,
    JSTechnologyEvidence,
    TechnologyEvidenceKind,
)
from hunterx.domain.javascript.tokenizer import JSToken, JSTokenizer, JSTokenType

#: Version extraction used when a versioned asset/CDN path is observed.
_VERSION_IN_PATH = re.compile(r"/([0-9]+\.[0-9]+(?:\.[0-9]+)?)")
_VERSION_IN_TAG = re.compile(r"@([0-9]+(?:\.[0-9]+){1,2})")
_VERSION_BARE = re.compile(r"\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9A-Za-z.-]+)?)\b")

#: A signature: ``(name, kind, category, pattern, confidence)``.
#: Patterns are matched against the whole source (case-insensitive).
_TECHNOLOGY_SIGNATURES: tuple[tuple[str, TechnologyEvidenceKind, str, str, float], ...] = (
    ("React", TechnologyEvidenceKind.FRAMEWORK, "ui-framework", r"\breact\b|React\.createElement|useState\s*\(|useEffect\s*\(", 0.9),
    ("React Router", TechnologyEvidenceKind.LIBRARY, "routing", r"react-router(?:-dom)?|createBrowserRouter|useNavigate\s*\(", 0.9),
    ("Vue", TechnologyEvidenceKind.FRAMEWORK, "ui-framework", r"\bVue\b|createApp\s*\(|vue-router", 0.9),
    ("Nuxt", TechnologyEvidenceKind.FRAMEWORK, "ui-framework", r"\bnuxt\b|@nuxt/", 0.9),
    ("Angular", TechnologyEvidenceKind.FRAMEWORK, "ui-framework", r"@angular/core|angular\.module\s*\(|NgModule", 0.9),
    ("Svelte", TechnologyEvidenceKind.FRAMEWORK, "ui-framework", r"\bsvelte\b", 0.85),
    ("Next.js", TechnologyEvidenceKind.FRAMEWORK, "ui-framework", r"next/router|next/link|__NEXT_DATA__", 0.9),
    ("Preact", TechnologyEvidenceKind.LIBRARY, "ui-framework", r"\bpreact\b|preact/compat", 0.9),
    ("jQuery", TechnologyEvidenceKind.LIBRARY, "dom", r"\bjquery\b|jquery\.min\.js|\.\./jquery", 0.9),
    ("Lodash", TechnologyEvidenceKind.LIBRARY, "utility", r"\blodash\b|lodash-es|_\s*\.\s*(?:map|filter|debounce)\s*\(", 0.85),
    ("Axios", TechnologyEvidenceKind.LIBRARY, "http-client", r"\baxios\b|axios\.(?:get|post|create)\s*\(", 0.9),
    ("SuperAgent", TechnologyEvidenceKind.LIBRARY, "http-client", r"\bsuperagent\b", 0.85),
    ("Webpack", TechnologyEvidenceKind.BUNDLER, "bundler", r"webpackJsonp|webpackHotUpdate|\bwebpack\b", 0.9),
    ("Vite", TechnologyEvidenceKind.BUNDLER, "bundler", r"\bvite\b|vite/client|import\.meta\.env", 0.8),
    ("Rollup", TechnologyEvidenceKind.BUNDLER, "bundler", r"\brollup\b|System\.register|SystemJS", 0.7),
    ("Parcel", TechnologyEvidenceKind.BUNDLER, "bundler", r"\bparcel\b", 0.7),
    ("Babel", TechnologyEvidenceKind.TRANSPILER, "tooling", r"@babel/|\"babel-core\"|babel-polyfill", 0.85),
    ("TypeScript", TechnologyEvidenceKind.COMPILER, "tooling", r"\btypescript\b|tslib|@types/|\.d\.ts\b", 0.8),
    ("ESLint", TechnologyEvidenceKind.TOOLING, "tooling", r"eslint|@typescript-eslint", 0.8),
    ("Redux", TechnologyEvidenceKind.LIBRARY, "state", r"redux|@reduxjs/toolkit|createStore\s*\(", 0.9),
    ("Zustand", TechnologyEvidenceKind.LIBRARY, "state", r"\bzustand\b|create\s*\(\s*\(set\)\s*=>", 0.8),
    ("MobX", TechnologyEvidenceKind.LIBRARY, "state", r"\bmobx\b|mobx-react", 0.85),
    ("Tailwind CSS", TechnologyEvidenceKind.LIBRARY, "css", r"tailwindcss|\btw-\b[a-z]+-\[|\btailwind\b", 0.85),
    ("Bootstrap", TechnologyEvidenceKind.LIBRARY, "css", r"\bbootstrap\b|bootstrap\.min\.css", 0.9),
    ("Material UI", TechnologyEvidenceKind.LIBRARY, "css", r"@mui/material|material-ui", 0.9),
    ("Ant Design", TechnologyEvidenceKind.LIBRARY, "css", r"antd\b|ant-design|antd/es/", 0.85),
    ("Chakra UI", TechnologyEvidenceKind.LIBRARY, "css", r"@chakra-ui/", 0.9),
    ("Storybook", TechnologyEvidenceKind.TOOLING, "tooling", r"storybook|@storybook/", 0.85),
    ("Jest", TechnologyEvidenceKind.TOOLING, "testing", r"\bjest\b|@jest/|jest\.fn\s*\(", 0.85),
    ("Vitest", TechnologyEvidenceKind.TOOLING, "testing", r"\bvitest\b", 0.85),
    ("Cypress", TechnologyEvidenceKind.TOOLING, "testing", r"\bcypress\b|Cypress\.", 0.85),
    ("Playwright", TechnologyEvidenceKind.TOOLING, "testing", r"\bplaywright\b|@playwright/", 0.85),
    ("Day.js", TechnologyEvidenceKind.LIBRARY, "date", r"\bdayjs\b|day\.js", 0.85),
    ("date-fns", TechnologyEvidenceKind.LIBRARY, "date", r"date-fns|date-fns-tz", 0.9),
    ("Moment", TechnologyEvidenceKind.LIBRARY, "date", r"\bmoment\b|moment\.min\.js", 0.85),
    ("Socket.IO", TechnologyEvidenceKind.LIBRARY, "realtime", r"socket\.io|io\s*\(\s*[\"'](?:wss?|https?)", 0.85),
    ("Firebase", TechnologyEvidenceKind.LIBRARY, "backend", r"firebase/|@firebase/|firebase\.app", 0.9),
    ("Apollo", TechnologyEvidenceKind.LIBRARY, "graphql", r"@apollo/client|apollo-boost|ApolloProvider", 0.9),
    ("GraphQL", TechnologyEvidenceKind.LIBRARY, "graphql", r"\bgraphql\b|GraphQLClient|gql\s*`", 0.85),
    ("Zod", TechnologyEvidenceKind.LIBRARY, "validation", r"\bzod\b|zod/", 0.9),
    ("Yup", TechnologyEvidenceKind.LIBRARY, "validation", r"\byup\b|yup/", 0.9),
    ("Three.js", TechnologyEvidenceKind.LIBRARY, "graphics", r"three\.(?:min\.)?js|THREE\.", 0.9),
    ("D3.js", TechnologyEvidenceKind.LIBRARY, "graphics", r"\bd3\b|d3\.(?:scale|select|axis|geo)\s*\(", 0.9),
    ("Chart.js", TechnologyEvidenceKind.LIBRARY, "graphics", r"chart\.js|Chart\.", 0.85),
    ("Recharts", TechnologyEvidenceKind.LIBRARY, "graphics", r"\brecharts\b", 0.9),
    ("i18next", TechnologyEvidenceKind.LIBRARY, "i18n", r"\bi18next\b|react-i18next", 0.9),
    ("Emotion", TechnologyEvidenceKind.LIBRARY, "css", r"@emotion/|emotion/", 0.9),
    ("Styled Components", TechnologyEvidenceKind.LIBRARY, "css", r"styled-components|styled\.(?:div|span|h1)\s*`", 0.9),
    ("Express", TechnologyEvidenceKind.RUNTIME, "backend", r"\bexpress\b|require\s*\(\s*[\"']express[\"']\s*\)", 0.9),
    ("Next.js API", TechnologyEvidenceKind.RUNTIME, "backend", r"pages/api|/api/.*\broute\.ts", 0.7),
    ("Service Worker", TechnologyEvidenceKind.RUNTIME, "pwa", r"serviceWorker\s*\.\s*register|self\.addEventListener\s*\(\s*[\"'](?:fetch|install|activate)", 0.9),
    ("WebAssembly", TechnologyEvidenceKind.RUNTIME, "runtime", r"WebAssembly\.", 0.95),
)

#: ``(name, category, confidence)`` — CDN hosts that identify a dependency.
_CDN_HOSTS: tuple[tuple[str, str, float], ...] = (
    ("cdnjs.cloudflare.com", "cdn", 0.95),
    ("unpkg.com", "cdn", 0.95),
    ("cdn.jsdelivr.net", "cdn", 0.95),
    ("cdn.skypack.dev", "cdn", 0.9),
    ("esm.sh", "cdn", 0.9),
)


@dataclass(frozen=True, slots=True)
class TechnologyDetection:
    """A single technology detection with its source evidence.

    Attributes:
        evidence: the technology evidence produced.
        source_offset: 0-based offset of the matched signature.
        source_value: the raw matched text (masked).

    """

    evidence: JSTechnologyEvidence
    source_offset: int = -1
    source_value: str = ""


class JSTechnologyDetector:
    """Detect frameworks, libraries and tooling from script content."""

    def detect(self, source: str, context: AnalyzeContext) -> list[TechnologyDetection]:
        """Return the technology detections found in ``source``."""
        detections: list[TechnologyDetection] = []
        seen: set[str] = set()
        lowered = source.lower()
        for name, kind, category, pattern, confidence in _TECHNOLOGY_SIGNATURES:
            match = re.search(pattern, source, re.IGNORECASE)
            if not match:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            version, version_confidence = _extract_version(lowered, match.start())
            evidence = JSTechnologyEvidence(
                kind=kind,
                name=name,
                version=version,
                version_confidence=version_confidence,
                category=category,
                evidence=(_evidence(source, match.start(), name, context),),
                confidence=confidence,
                source=context.source_label,
                tool_id=context.tool_id,
                target_key=context.target_key,
                correlation_id=context.correlation_id,
                mission_id=context.mission_id,
            )
            detections.append(
                TechnologyDetection(
                    evidence=evidence,
                    source_offset=match.start(),
                    source_value=source[match.start() : match.end()][:120],
                )
            )
        return detections


class JSDependencyDetector:
    """Extract package dependencies from import/require and CDN references."""

    def __init__(self, *, tokenizer: JSTokenizer | None = None) -> None:
        self._tokenizer = tokenizer or JSTokenizer()

    def detect(self, source: str, context: AnalyzeContext) -> list[JSDependency]:
        """Return the dependency indicators found in ``source``."""
        tokens = self._tokenizer.tokenize(source, file=context.file)
        dependencies: list[JSDependency] = []
        seen: set[str] = set()

        # import ... from "pkg"  /  import "pkg"  /  require("pkg")
        keywords = [token for token in tokens if token.token_type is JSTokenType.KEYWORD and token.value in ("import", "require")]
        values = [token for token in tokens if token.is_value()]
        for kw in keywords:
            target = _following_value(kw, values)
            if target is None:
                continue
            package = _normalize_package(target.value)
            if not package:
                continue
            if _is_relative(package) or _is_asset_path(package):
                continue
            key = package
            if key in seen:
                continue
            seen.add(key)
            dependencies.append(
                _make_dependency(
                    source,
                    target,
                    package,
                    context,
                    origin="import" if kw.value == "import" else "require",
                    offset=kw.offset,
                )
            )

        # CDN references
        for token in values:
            lowered = token.value.lower()
            host = _cdn_host(lowered)
            if host is None:
                continue
            package = _package_from_cdn_path(token.value)
            key = f"cdn:{host}:{package}"
            if key in seen:
                continue
            seen.add(key)
            dependencies.append(
                _make_dependency(
                    source,
                    token,
                    package or host,
                    context,
                    origin="cdn",
                    offset=token.offset,
                )
            )
        return dependencies


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _make_dependency(
    source: str,
    token: JSToken,
    name: str,
    context: AnalyzeContext,
    *,
    origin: str,
    offset: int,
) -> JSDependency:
    version = _extract_version_from_name(name)[0]
    return JSDependency(
        name=name,
        version=version,
        source=origin,
        evidence=(_evidence(source, offset, token, context),),
        confidence=0.9 if origin == "cdn" else 0.85,
        source_=context.source_label,
        tool_id=context.tool_id,
        target_key=context.target_key,
        correlation_id=context.correlation_id,
        mission_id=context.mission_id,
    )


def _following_value(anchor: JSToken, values: list[JSToken]) -> JSToken | None:
    """Return the next value token within a short window after ``anchor``."""
    for value in values:
        if value.offset > anchor.offset and value.offset - anchor.offset < 80:
            return value
    return None


def _normalize_package(value: str) -> str:
    """Normalize a package specifier to ``@scope/name`` form."""
    stripped = value.strip()
    if not stripped or any(char in stripped for char in ("\n", " ")):
        return ""
    return stripped


def _is_relative(value: str) -> bool:
    """Return ``True`` for relative module specifiers (``./``, ``../``)."""
    return value.startswith(("./", "../", "/"))


def _is_asset_path(value: str) -> bool:
    """Return ``True`` when the specifier points at a static asset."""
    lowered = value.lower()
    return any(lowered.endswith(ext) for ext in (".css", ".json", ".svg", ".png", ".jpg", ".wasm", ".html"))


def _cdn_host(lowered: str) -> str | None:
    for host, _category, _confidence in _CDN_HOSTS:
        if host in lowered:
            return host
    return None


def _package_from_cdn_path(value: str) -> str:
    """Extract a package name from a CDN URL path when present."""
    import urllib.parse

    try:
        parsed = urllib.parse.urlsplit(value if "://" in value else f"https:{value}")
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            return ""
        # jsdelivr/unpkg namespace segments that are not part of the name.
        while parts and parts[0] in ("npm", "gh", "github"):
            parts = parts[1:]
        if not parts:
            return ""
        if parts[0].startswith("@"):
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
            return parts[0]
        return parts[0]
    except ValueError:
        return ""


def _extract_version(source: str, near: int) -> tuple[str, str]:
    """Best-effort version extraction near an offset in the source."""
    window = source[max(0, near - 60) : near + 60]
    match = _VERSION_IN_PATH.search(window)
    if match:
        return match.group(1), "probable"
    match = _VERSION_IN_TAG.search(window)
    if match:
        return match.group(1), "confirmed"
    match = _VERSION_BARE.search(window)
    if match:
        return match.group(1), "probable"
    return "", "unknown"


def _extract_version_from_name(name: str) -> tuple[str, str]:
    """Extract a version from a package name/version string."""
    if "@" in name and not name.startswith("@"):
        match = _VERSION_IN_TAG.search(name)
        if match:
            return match.group(1), "confirmed"
    return "", "unknown"


def _evidence(
    source: str,
    offset: int,
    label: str,
    context: AnalyzeContext,
) -> JSEvidence:
    """Build a technology evidence fragment from a source offset."""
    line, column = _location(source, offset)
    location = f"{context.file}:{line}:{column}" if context.file else f"{line}:{column}"
    return JSEvidence(
        evidence_type="signature",
        value=label,
        location=location,
        offset=offset,
        snippet=source[offset : offset + 60] + ("..." if len(source) - offset > 60 else ""),
        rule_id="tech-signature",
        source=context.source_label,
        tool_id=context.tool_id,
        confidence=1.0,
    )


def _location(source: str, offset: int) -> tuple[int, int]:
    """Return ``(line, column)`` for a 0-based ``offset`` in ``source``."""
    line = 1
    column = 1
    for char in source[: min(offset, len(source))]:
        if char == "\n":
            line += 1
            column = 1
        else:
            column += 1
    return line, column
