# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process HTTP page fetcher for the web crawler.

The fetcher returns a :class:`FetchedPage` — the unit of content the in-process
crawler walks. Like the fingerprinting fetcher it is an injectable seam
(``WebFetchFn``) so the crawler adapter stays fully testable without a network:
unit tests inject a fake fetch returning golden pages.

Redirects are captured rather than silently followed: the fetcher stops at the
first ``3xx`` and reports the ``Location`` so the crawler can record a
:class:`~hunterx.domain.web.models.Redirect` and decide in-scope continuation
itself. Nothing returned by the server is ever executed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from hunterx.shared.time import utcnow_iso

#: Fetch seam: ``(url, timeout_s, **kwargs) -> FetchedPage``. Keyword
#: arguments (``cookies``/``headers``/``method``/``data``) are optional and
#: only supported by the in-process fetcher; adapters must tolerate fakes that
#: accept only the two positional arguments.
WebFetchFn = Callable[..., "FetchedPage"]

#: Default per-request timeout in seconds.
_DEFAULT_TIMEOUT = 10.0

#: Default body read cap in bytes (content beyond this is truncated).
_DEFAULT_BODY_LIMIT = 2_000_000

#: User agent used for in-process crawler fetches.
_USER_AGENT = "hunterx-crawler/7.0"

#: HTTP statuses that terminate a fetch with a redirect observation.
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(slots=True)
class FetchedPage:
    """The raw result of fetching one URL.

    Attributes:
        url: canonical URL that was requested.
        status_code: HTTP status (``0`` when the fetch failed to connect).
        headers: lowercased response headers.
        cookies: session cookies set by the response (``Set-Cookie`` parsed
            into name/value pairs).
        content: decoded body (may be empty).
        content_type: response ``Content-Type`` header value.
        redirect_url: canonical ``Location`` for redirect responses.
        error: connection/transport error message.
        fetched_at: UTC ISO fetch timestamp.

    """

    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    content: str = ""
    content_type: str = ""
    redirect_url: str = ""
    error: str = ""
    fetched_at: str = field(default_factory=utcnow_iso)

    @property
    def is_redirect(self) -> bool:
        """Return ``True`` when the response is an HTTP redirect."""
        return self.status_code in _REDIRECT_STATUSES and bool(self.redirect_url)


class _StopAtRedirectError(HTTPError):
    """Raised internally to halt a fetch at a redirect response."""

    def __init__(self, url: str, code: int, location: str, headers: object | None = None) -> None:
        # HTTPError.__init__ expects a parsed header object; constructing the
        # exception attributes directly keeps this transport-internal marker
        # minimal and avoids importing email parsing machinery.
        self.url = url
        self.code = code
        self.msg = f"Redirect to {location}"
        self.redirect_location = location
        #: Raw redirect response headers (``Set-Cookie`` etc.) so the caller
        #: can capture session cookies set on the redirect.
        self.headers = headers or {}


class _CaptureRedirectHandler(HTTPRedirectHandler):
    """Redirect handler that stops at the first ``3xx`` instead of following."""

    def redirect_request(self, req: Request, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        location = getattr(headers, "get", lambda key, default: default)("Location", newurl)
        raise _StopAtRedirectError(req.full_url, code, location, headers=headers)

class HttpPageFetcher:
    """Fetch an HTTP(S) URL and return a :class:`FetchedPage` (never raises)."""

    def __init__(
        self,
        *,
        user_agent: str = _USER_AGENT,
        body_limit: int = _DEFAULT_BODY_LIMIT,
    ) -> None:
        self._user_agent = user_agent
        self._body_limit = body_limit
        self._opener = build_opener(_CaptureRedirectHandler())

    def fetch(
        self,
        url: str,
        timeout_s: float = _DEFAULT_TIMEOUT,
        *,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> FetchedPage:
        """Fetch ``url`` and return a page (connection errors yield status 0).

        Args:
            url: the target URL to fetch.
            timeout_s: per-request timeout in seconds.
            method: HTTP method (``GET``/``POST``/...).
            data: request body for ``POST``/``PUT`` (form-encoded bytes).
            headers: extra request headers (e.g. ``Origin``, ``Cookie``).
            cookies: session cookies merged into the ``Cookie`` header.

        """
        timeout = timeout_s or _DEFAULT_TIMEOUT
        request_headers = {"User-Agent": self._user_agent}
        if headers:
            request_headers.update(headers)
        if cookies:
            cookie_value = "; ".join(f"{name}={value}" for name, value in cookies.items())
            request_headers["Cookie"] = cookie_value
        request = Request(url, headers=request_headers, data=data, method=method.upper())
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                headers, cookies = _response_headers_and_cookies(response)
                content = response.read(self._body_limit)
                content_type = headers.get("content-type", "").split(";", 1)[0].strip()
        except _StopAtRedirectError as redirect:
            status = redirect.code
            headers, cookies = _response_headers_and_cookies(redirect.headers)
            return FetchedPage(
                url=url,
                status_code=status,
                headers=headers,
                cookies=cookies,
                content_type=headers.get("content-type", "").split(";", 1)[0].strip(),
                redirect_url=redirect.redirect_location,
                fetched_at=utcnow_iso(),
            )
        except HTTPError as error:
            headers, cookies = _response_headers_and_cookies(error.headers)
            return FetchedPage(
                url=url,
                status_code=error.code,
                headers=headers,
                cookies=cookies,
                error=f"HTTP {error.code}",
                fetched_at=utcnow_iso(),
            )
        except (URLError, OSError, ValueError) as error:
            return FetchedPage(url=url, error=str(error), fetched_at=utcnow_iso())
        except Exception as error:  # noqa: BLE001 - fetch failures must never escape
            return FetchedPage(url=url, error=str(error), fetched_at=utcnow_iso())
        return FetchedPage(
            url=url,
            status_code=int(status),
            headers=headers,
            cookies=cookies,
            content=content.decode("utf-8", errors="replace"),
            content_type=content_type,
            fetched_at=utcnow_iso(),
        )


def _response_headers_and_cookies(response: object) -> tuple[dict[str, str], dict[str, str]]:
    """Extract lowercased headers and parsed ``Set-Cookie`` values.

    ``Set-Cookie`` may appear multiple times; every value is parsed so the
    full session-cookie jar (e.g. a security flag plus the session id) is
    captured, not just the last header.
    """
    headers: dict[str, str] = {}
    set_cookie_values: list[str] = []
    header_source = getattr(response, "headers", None)
    items = header_source.items() if header_source is not None else getattr(response, "items", lambda: [])()
    for name, value in items:
        key = str(name).lower()
        if key == "set-cookie":
            set_cookie_values.append(str(value))
        headers[key] = str(value)
    cookies: dict[str, str] = {}
    for raw in set_cookie_values:
        for name, value in _split_set_cookie(raw):
            # Later Set-Cookie headers override earlier ones (browser/cookie-jar
            # semantics): a session-regenerated app sends the same name twice
            # and the last value is the live session.
            cookies[name] = value
    return headers, cookies


def _split_set_cookie(raw: str) -> list[tuple[str, str]]:
    """Extract the primary ``(name, value)`` pair from one ``Set-Cookie``.

    Attributes (``Path``, ``HttpOnly``, ``Expires=...``, ...) are ignored —
    only the cookie pair itself is needed for session replay. The primary
    pair is the first ``name=value`` in the header; a comma inside an
    ``Expires=`` date never precedes it.
    """
    segment = raw.strip()
    if not segment or "=" not in segment:
        return []
    name, _, remainder = segment.partition("=")
    value = remainder.split(";", 1)[0].strip()
    return [(name.strip(), value)] if name.strip() else []
