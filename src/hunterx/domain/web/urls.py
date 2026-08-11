# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""URL normalization for the web crawling capability.

The normalizer is deterministic and stateless: it collapses equivalent
spellings of a URL (default ports, fragments, query-key ordering, scheme and
host casing, trailing slash) into one canonical form so correlation never treats
``https://EXAMPLE.com:443/a?b=2&a=1`` and ``https://example.com/a?a=1&b=2`` as
different resources. It deliberately keeps query values intact — only the key
order is canonicalized — so parameter discovery never loses data.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

#: Schemes with well-known default ports removed during canonicalization.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}

#: Schemes this capability is allowed to model.
_SAFE_SCHEMES = frozenset({"http", "https", "ws", "wss"})


@dataclass(frozen=True, slots=True)
class ParsedURL:
    """A decomposed, normalized URL.

    Attributes:
        scheme: lowercase scheme (``https``).
        host: lowercase host without trailing dot.
        port: explicit port when non-default.
        path: normalized path (empty becomes ``/``).
        query: canonicalized query string (may be empty).
        fragment: always empty (fragments are never indexed).
        netloc: ``host[:port]`` in canonical form.

    """

    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str = ""

    @property
    def netloc(self) -> str:
        """Return the canonical ``host[:port]`` network location."""
        if self.port is not None:
            return f"{self.host}:{self.port}"
        return self.host

    @property
    def origin(self) -> str:
        """Return the RFC 6454-style origin (``scheme://host[:port]``)."""
        return f"{self.scheme}://{self.netloc}"

    @property
    def url(self) -> str:
        """Return the full canonical URL string."""
        return urlunsplit((self.scheme, self.netloc, self.path, self.query, self.fragment))


class URLNormalizer:
    """Canonicalize URLs for storage, deduplication and scoping.

    Configuration (``keep_query``, ``sort_query``, ``strip_trailing_slash``)
    is fixed at construction so every observation in a run shares the same
    policy; the defaults follow the conservative posture: keep query data,
    sort query keys, and strip trailing slashes.
    """

    def __init__(
        self,
        *,
        keep_query: bool = True,
        sort_query: bool = True,
        strip_trailing_slash: bool = True,
        default_scheme: str = "https",
    ) -> None:
        self._keep_query = keep_query
        self._sort_query = sort_query
        self._strip_trailing_slash = strip_trailing_slash
        self._default_scheme = default_scheme

    def parse(self, url: str, *, base: str | None = None) -> ParsedURL:
        """Resolve ``url`` (against ``base`` when relative) and normalize it.

        Raises:
            ValueError: when the URL cannot be normalized (missing host, or an
                unsupported scheme).

        """
        raw = url.strip()
        if not raw:
            raise ValueError("empty URL")
        resolved = raw
        if base:
            from urllib.parse import urljoin

            resolved = urljoin(base, raw)
        parts = urlsplit(resolved)
        scheme = (parts.scheme or self._default_scheme).lower()
        if scheme not in _SAFE_SCHEMES:
            raise ValueError(f"unsupported URL scheme '{scheme}'")
        host = (parts.hostname or "").rstrip(".").lower()
        if not host:
            raise ValueError(f"URL has no host: {url}")
        try:
            port = parts.port
        except ValueError:
            port = None
        default_port = _DEFAULT_PORTS.get(scheme)
        if port is not None and port == default_port:
            port = None
        path = unquote(parts.path) if parts.path else ""
        if not path:
            path = "/"
        if self._strip_trailing_slash and len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
            if not path:
                path = "/"
        query = ""
        if self._keep_query and parts.query:
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            if self._sort_query:
                pairs = sorted(pairs, key=lambda item: (item[0], item[1]))
            query = urlencode(pairs)
        return ParsedURL(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            query=query,
        )

    def normalize(self, url: str, *, base: str | None = None) -> str:
        """Return the canonical string form of ``url``."""
        return self.parse(url, base=base).url

    def origin(self, url: str, *, base: str | None = None) -> str:
        """Return the canonical origin (``scheme://host[:port]``) of ``url``."""
        return self.parse(url, base=base).origin

    def host(self, url: str, *, base: str | None = None) -> str:
        """Return the canonical lowercase host of ``url``."""
        return self.parse(url, base=base).host

    def is_relative(self, url: str) -> bool:
        """Return ``True`` when ``url`` is a relative reference (no scheme)."""
        return bool(url.strip()) and not urlsplit(url.strip()).scheme


def query_to_pairs(query: str) -> tuple[tuple[str, str], ...]:
    """Return the ordered ``(name, value)`` pairs of a query string."""
    return tuple(parse_qsl(query, keep_blank_values=True))


def is_supported_scheme(url: str) -> bool:
    """Return ``True`` when ``url`` uses a supported HTTP(S)/WS(S) scheme."""
    scheme = urlsplit(url.strip()).scheme.lower() or "https"
    return scheme in _SAFE_SCHEMES
