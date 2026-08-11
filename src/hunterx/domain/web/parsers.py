# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deterministic, dependency-free content parsing for the web crawler.

Extracts links, forms, script sources, parameters, robots.txt rules, sitemap
URLs, WebSocket/GraphQL/API endpoints and authentication indicators from HTML,
plain text and header maps. Every function is a pure transform: given content
and a base URL it returns canonical observations, never performing I/O.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from html.parser import HTMLParser
from typing import Any

from hunterx.domain.web.models import (
    APIEndpoint,
    AuthenticationBoundary,
    HTTPMethod,
)
from hunterx.domain.web.urls import URLNormalizer, query_to_pairs

#: Scheme-relative / protocol-relative prefix.
_PROTOCOL_RELATIVE = re.compile(r"^//")

#: Paths that strongly indicate an API surface.
_API_PATH_RE = re.compile(
    r"(/api/|/rest/|/v[0-9]+/|/graphql$|/rpc/|/json$|\.json$|/webhook|/callback|/internal/|/services/)",
    re.IGNORECASE,
)

#: Content types whose bodies are parsed for links.
_PARSEABLE_CONTENT_TYPES = ("text/html", "application/xhtml", "text/plain", "application/json")

#: WebSocket handshake headers observed on connections.
_WEBSOCKET_HEADER_NAMES = ("upgrade", "sec-websocket-protocol", "sec-websocket-extensions")


class _HtmlCollector(HTMLParser):
    """Collect link-like attributes from an HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: set[str] = set()
        self.script_sources: set[str] = set()
        self.images: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # noqa: C901
        attributes = {key.lower(): (value or "") for key, value in attrs}
        href = attributes.get("href")
        if tag in ("a", "link") and href:
            self.links.add(href)
        src = attributes.get("src")
        if tag == "script" and src:
            self.script_sources.add(src)
        if tag == "img" and src:
            self.images.add(src)
        if tag == "iframe" and src:
            self.links.add(src)
        if tag == "form":
            self._current_form = {
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "get").upper(),
                "fields": [],
            }
        if tag in ("input", "textarea", "select") and self._current_form is not None:
            field: dict[str, Any] = {
                "name": attributes.get("name") or "",
                "type": attributes.get("type") or ("textarea" if tag == "textarea" else "text"),
                "required": attributes.get("required") is not None,
                "value": attributes.get("value") or "",
            }
            if tag == "textarea":
                field["type"] = "textarea"
            self._current_form["fields"].append(field)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def extract_links(html: str, base_url: str, normalizer: URLNormalizer | None = None) -> set[str]:
    """Return canonical absolute URLs referenced by an HTML document."""
    normalizer = normalizer or URLNormalizer()
    collector = _HtmlCollector()
    try:
        collector.feed(html)
    except Exception:  # noqa: BLE001 - malformed documents must not break a crawl
        return set()
    links: set[str] = set()
    for raw in collector.links:
        links.update(_resolve_candidates(raw, base_url, normalizer))
    return links


def extract_script_sources(html: str, base_url: str, normalizer: URLNormalizer | None = None) -> set[str]:
    """Return canonical script source URLs referenced by an HTML document."""
    normalizer = normalizer or URLNormalizer()
    collector = _HtmlCollector()
    try:
        collector.feed(html)
    except Exception:  # noqa: BLE001
        return set()
    sources: set[str] = set()
    for raw in collector.script_sources:
        sources.update(_resolve_candidates(raw, base_url, normalizer))
    return sources


def extract_forms(
    html: str,
    base_url: str,
    normalizer: URLNormalizer | None = None,
) -> list[dict[str, Any]]:
    """Return forms as ``{action, method, fields}`` maps."""
    normalizer = normalizer or URLNormalizer()
    collector = _HtmlCollector()
    try:
        collector.feed(html)
    except Exception:  # noqa: BLE001
        return []
    forms: list[dict[str, Any]] = []
    for form in collector.forms:
        action = str(form.get("action") or "")
        if action:
            try:
                action = normalizer.normalize(action, base=base_url)
            except ValueError:
                action = ""
        fields = [field for field in form["fields"] if field.get("name")]
        forms.append({"action": action, "method": form["method"], "fields": fields})
    return forms


def extract_query_parameters(url: str) -> tuple[tuple[str, str], ...]:
    """Return the ordered ``(name, value)`` pairs of a URL's query string."""
    from urllib.parse import urlsplit

    return query_to_pairs(urlsplit(url).query)


def parameter_names(url: str) -> tuple[str, ...]:
    """Return the distinct parameter names on a URL."""
    seen: list[str] = []
    for name, _value in extract_query_parameters(url):
        if name not in seen:
            seen.append(name)
    return tuple(seen)


def is_interesting_parameter(name: str) -> bool:
    """Return ``True`` for parameters worth flagging in reports."""
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    if lowered in (
        "id",
        "user",
        "username",
        "user_id",
        "uid",
        "file",
        "filename",
        "upload",
        "redirect",
        "url",
        "next",
        "return",
        "callback",
        "path",
        "page",
        "admin",
        "role",
        "token",
    ):
        return True
    return any(part in lowered for part in ("session", "token", "password", "secret", "key", "auth"))


def parse_robots(text: str, base_url: str = "", normalizer: URLNormalizer | None = None) -> dict[str, Any]:
    """Parse a robots.txt document.

    Returns:
        ``{"allow": [...], "disallow": [...], "sitemaps": [...],
        "user_agents": [...], "respectable": bool}``.

    """
    normalizer = normalizer or URLNormalizer()
    allow: list[str] = []
    disallow: list[str] = []
    sitemaps: list[str] = []
    user_agents: list[str] = []
    current_agent: str = "*"
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "user-agent":
            current_agent = value.lower()
            if value.lower() not in user_agents:
                user_agents.append(value.lower())
        elif key == "allow":
            allow.append(value)
        elif key == "disallow":
            disallow.append(value)
        elif key == "sitemap":
            try:
                sitemaps.append(normalizer.normalize(value))
            except ValueError:
                sitemaps.append(value)
    return {
        "allow": allow,
        "disallow": disallow,
        "sitemaps": sitemaps,
        "user_agents": user_agents,
        "respectable": current_agent == "*" or bool(user_agents),
    }


def parse_sitemap(text: str, base_url: str = "", normalizer: URLNormalizer | None = None) -> tuple[str, ...]:
    """Return canonical URLs declared by a sitemap document (``<loc>`` entries)."""
    normalizer = normalizer or URLNormalizer()
    locations = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, flags=re.IGNORECASE | re.DOTALL)
    urls: list[str] = []
    for raw in locations:
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            urls.append(normalizer.normalize(candidate))
        except ValueError:
            continue
    return tuple(urls)


def detect_graphql(url: str, content_type: str = "") -> bool:
    """Return ``True`` when ``url`` or its response indicates a GraphQL endpoint."""
    path = url.split("?", 1)[0].rstrip("/")
    if path.endswith("/graphql") or "/graphql/" in path:
        return True
    return "graphql" in url.lower()


def detect_websocket_urls(html: str) -> set[str]:
    """Return ``ws://`` / ``wss://`` URLs referenced by an HTML document."""
    matches = re.findall(r"(?:wss?://[^\s'\"<>)`]+)", html)
    return {match.rstrip(".,;") for match in matches}


def detect_websocket_headers(headers: Mapping[str, str]) -> bool:
    """Return ``True`` when a response indicates a WebSocket handshake."""
    lowered = {str(key).lower(): str(value).lower() for key, value in (headers or {}).items()}
    if "upgrade" in lowered and lowered["upgrade"] == "websocket":
        return True
    return any(name in lowered for name in _WEBSOCKET_HEADER_NAMES)


def detect_api_urls(
    html: str,
    base_url: str,
    normalizer: URLNormalizer | None = None,
    *,
    content_type: str = "",
) -> set[str]:
    """Return canonical URLs that look like API endpoints in an HTML document."""
    normalizer = normalizer or URLNormalizer()
    candidates: set[str] = set()
    collector = _HtmlCollector()
    try:
        collector.feed(html)
    except Exception:  # noqa: BLE001
        return candidates
    for raw in list(collector.links) + list(collector.images):
        if _API_PATH_RE.search(raw):
            for resolved in _resolve_candidates(raw, base_url, normalizer):
                candidates.add(resolved)
    return candidates


def detect_auth_boundary(
    url: str,
    *,
    status_code: int | None = None,
    headers: Mapping[str, str] | None = None,
    html: str = "",
    normalizer: URLNormalizer | None = None,
) -> AuthenticationBoundary | None:
    """Detect whether ``url`` gates access behind authentication."""
    normalizer = normalizer or URLNormalizer()
    indicators: list[str] = []
    scheme = "session"
    if status_code in (401, 403):
        indicators.append(f"HTTP {status_code}")
    for key, value in (headers or {}).items():
        lowered = str(key).lower()
        if lowered == "www-authenticate" and value:
            indicators.append(f"WWW-Authenticate: {value}")
            value_lower = str(value).lower()
            if "basic" in value_lower:
                scheme = "basic"
            elif "bearer" in value_lower:
                scheme = "bearer"
            else:
                scheme = "challenge"
        elif lowered == "set-cookie" and value:
            indicators.append("Set-Cookie observed")
        elif lowered == "location" and value:
            lowered_value = str(value).lower()
            if "login" in lowered_value or "signin" in lowered_value or "auth" in lowered_value:
                indicators.append(f"redirect to {value}")
                scheme = "login-redirect"
    if "login" in html.lower()[:20000] or "password" in html.lower()[:20000]:
        indicators.append("login form present")
        scheme = "login-form"
    if not indicators:
        return None
    return AuthenticationBoundary(
        url=url,
        scheme=scheme,
        indicators=tuple(indicators),
        confidence=min(1.0, 0.55 + 0.1 * len(indicators)),
    )


def build_api_endpoint(
    url: str,
    *,
    method: str = "GET",
    content_type: str = "",
    response_content_type: str = "",
    parameters: Sequence[Mapping[str, Any]] = (),
    evidence: Sequence[Mapping[str, Any]] = (),
    confidence: float = 1.0,
) -> APIEndpoint:
    """Build a canonical :class:`APIEndpoint` for a detected API URL."""
    return APIEndpoint(
        url=url,
        method=_http_method(method),
        content_type=content_type,
        response_content_type=response_content_type,
        parameters=tuple(dict(item) for item in parameters),
        evidence=tuple(dict(item) for item in evidence),
        confidence=confidence,
    )


def should_parse_content_type(content_type: str) -> bool:
    """Return ``True`` when a content type is worth parsing for links."""
    lowered = (content_type or "").lower()
    return any(lowered.startswith(prefix) for prefix in _PARSEABLE_CONTENT_TYPES)


def _resolve_candidates(raw: str, base_url: str, normalizer: URLNormalizer) -> set[str]:
    """Resolve one or more candidate URL strings to canonical URLs."""
    resolved: set[str] = set()
    for candidate in _split_candidates(raw):
        try:
            resolved.add(normalizer.normalize(candidate, base=base_url))
        except ValueError:
            continue
    return resolved


def _split_candidates(raw: str) -> list[str]:
    """Split a space/comma separated attribute into individual URLs."""
    return [item for item in re.split(r"[,\s]+", raw.strip()) if item]


def _http_method(value: str) -> HTTPMethod:
    try:
        return HTTPMethod(value.upper())
    except ValueError:
        return HTTPMethod.UNKNOWN
