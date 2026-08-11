# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Normalization for JavaScript intelligence artifacts.

Turns raw, tool-produced values into canonical forms: URL resolution (relative
paths joined against a base), hostname/domain canonicalization, and endpoint /
route / dependency key normalization. Normalization is idempotent and pure; the
original value is preserved on the finding and only the canonical key is
derived.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from hunterx.domain.javascript.models import JSEndpoint, JSRoute

#: Route parameter placeholders (``:id``, ``{id}``) replaced during keying.
_PARAM_PATTERN = re.compile(r"(?::[A-Za-z0-9_]+|\{[A-Za-z0-9_]+\})")

#: Trailing-slash / query / hash cleanup.
_TRAILING = re.compile(r"[/?#]+$")


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    """A resolved URL plus its canonical key.

    Attributes:
        resolved: the absolute URL after joining against a base.
        path: the canonical path component.
        host: canonical lowercased hostname.
        scheme: URL scheme (``http``/``https``/``ws``/...).

    """

    resolved: str
    path: str
    host: str
    scheme: str


class JSNormalizer:
    """Normalize endpoints, routes and domain references."""

    def __init__(self, *, base_url: str = "") -> None:
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        """Return the configured base URL used for relative-path joins."""
        return self._base_url

    def resolve(self, value: str) -> NormalizedUrl:
        """Resolve ``value`` against the base URL and canonicalize it."""
        stripped = str(value or "").strip()
        scheme, host, path, resolved = _resolve_url(stripped, self._base_url)
        return NormalizedUrl(
            resolved=resolved,
            path=path,
            host=host,
            scheme=scheme,
        )

    def normalize_endpoint(self, endpoint: JSEndpoint) -> JSEndpoint:
        """Return ``endpoint`` with a canonical absolute URL and key.

        The original ``url`` attribute is preserved; ``base_url`` is populated
        when the reference was relative.
        """
        from dataclasses import replace

        if "://" in endpoint.url or endpoint.url.startswith("//"):
            return endpoint
        resolved = self.resolve(endpoint.url)
        if not resolved.host:
            return endpoint
        return replace(
            endpoint,
            url=resolved.resolved,
            base_url=self._base_url,
        )

    def route_key(self, route: JSRoute) -> str:
        """Return the canonical deduplication key for a route."""
        pattern = _PARAM_PATTERN.sub(":param", route.route)
        return f"route:{route.framework.value}:{pattern}"

    def endpoint_key(self, endpoint: JSEndpoint) -> str:
        """Return the canonical deduplication key for an endpoint."""
        resolved = self.resolve(endpoint.url)
        path = resolved.path or endpoint.url
        return f"endpoint:{endpoint.kind.value}:{endpoint.method.upper()}:{path}"

    def domain_key(self, domain: str) -> str:
        """Return the canonical key for a domain."""
        return domain.strip().lower().rstrip(".")


def _resolve_url(value: str, base_url: str) -> tuple[str, str, str, str]:
    """Resolve ``value`` against ``base_url``.

    Returns ``(scheme, host, path, resolved)``.
    """
    stripped = value.strip()
    if stripped.startswith("//"):
        scheme = "https"
        if ":" in base_url:
            scheme = urllib.parse.urlsplit(base_url).scheme or "https"
        stripped = f"{scheme}:{stripped}"
    if "://" in stripped:
        try:
            parsed = urllib.parse.urlsplit(stripped)
            host = (parsed.hostname or "").lower()
            return parsed.scheme.lower(), host, parsed.path, stripped
        except ValueError:
            return "", "", "", stripped
    # relative path — join against base
    if base_url and "://" in base_url:
        try:
            joined = urllib.parse.urljoin(base_url, stripped)
            parsed = urllib.parse.urlsplit(joined)
            host = (parsed.hostname or "").lower()
            return parsed.scheme.lower(), host, parsed.path, joined
        except ValueError:
            pass
    return "", "", stripped, stripped
