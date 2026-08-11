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

#: Fetch seam: ``(url, timeout_s) -> FetchedPage``.
WebFetchFn = Callable[[str, float], "FetchedPage"]

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
        content: decoded body (may be empty).
        content_type: response ``Content-Type`` header value.
        redirect_url: canonical ``Location`` for redirect responses.
        error: connection/transport error message.
        fetched_at: UTC ISO fetch timestamp.

    """

    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
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

    def __init__(self, url: str, code: int, location: str) -> None:
        # HTTPError.__init__ expects a parsed header object; constructing the
        # exception attributes directly keeps this transport-internal marker
        # minimal and avoids importing email parsing machinery.
        self.url = url
        self.code = code
        self.msg = f"Redirect to {location}"
        self.redirect_location = location


class _CaptureRedirectHandler(HTTPRedirectHandler):
    """Redirect handler that stops at the first ``3xx`` instead of following."""

    def redirect_request(self, req: Request, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        location = getattr(headers, "get", lambda key, default: default)("Location", newurl)
        raise _StopAtRedirectError(req.full_url, code, location)

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

    def fetch(self, url: str, timeout_s: float = _DEFAULT_TIMEOUT) -> FetchedPage:
        """Fetch ``url`` and return a page (connection errors yield status 0)."""
        timeout = timeout_s or _DEFAULT_TIMEOUT
        request = Request(url, headers={"User-Agent": self._user_agent})
        try:
            with self._opener.open(request, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                headers = {str(name).lower(): str(value) for name, value in response.headers.items()}
                content = response.read(self._body_limit)
                content_type = headers.get("content-type", "").split(";", 1)[0].strip()
        except _StopAtRedirectError as redirect:
            status = redirect.code
            headers = {
                str(name).lower(): str(value)
                for name, value in (redirect.headers or {}).items()
            }
            return FetchedPage(
                url=url,
                status_code=status,
                headers=headers,
                content_type=headers.get("content-type", "").split(";", 1)[0].strip(),
                redirect_url=redirect.redirect_location,
                fetched_at=utcnow_iso(),
            )
        except HTTPError as error:
            return FetchedPage(
                url=url,
                status_code=error.code,
                headers={str(name).lower(): str(value) for name, value in (error.headers or {}).items()},
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
            content=content.decode("utf-8", errors="replace"),
            content_type=content_type,
            fetched_at=utcnow_iso(),
        )
