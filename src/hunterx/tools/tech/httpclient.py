# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process HTTP fetcher for the signature detector.

Collects an :class:`~hunterx.domain.technology.detector.HttpEvidence` bundle
(status, headers, body, title, meta, cookies, script references and TLS
certificate subject/issuer) with the Python standard library. The fetch is an
injectable seam (``FetchFn``) so the signature adapter stays fully testable
without a network: unit tests inject a fake fetch returning golden evidence.

The fetcher treats every response as untrusted data — nothing returned by the
server is ever executed or interpolated into a command line.
"""

from __future__ import annotations

import re
import socket  # nosec B105  # the fetcher only reads public TLS certificate metadata
import ssl
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from hunterx.domain.technology.detector import HttpEvidence
from hunterx.shared.time import utcnow_iso

#: Fetch seam: ``(url, timeout_s) -> HttpEvidence``.
FetchFn = Callable[[str, float], HttpEvidence]

#: Default per-request timeout in seconds.
_DEFAULT_TIMEOUT = 10.0

#: Title extraction pattern.
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
#: Meta tag extraction pattern.
_META_RE = re.compile(r'<meta[^>]+(?:name|property)="([^"]+)"[^>]+content="([^"]*)"', re.IGNORECASE)
#: Script reference extraction pattern.
_SCRIPT_RE = re.compile(r'<script[^>]+src="([^"]+)"', re.IGNORECASE)

#: User agent used for in-process fetches.
_USER_AGENT = "hunterx-fingerprint/7.0"


class HttpFetcher:
    """Fetch an HTTP(S) URL and build an :class:`HttpEvidence` bundle.

    Usage::

        fetcher = HttpFetcher()
        evidence = fetcher.fetch("https://example.com", timeout_s=10)
    """

    def __init__(self, *, user_agent: str = _USER_AGENT) -> None:
        self._user_agent = user_agent

    def fetch(self, url: str, timeout_s: float = _DEFAULT_TIMEOUT) -> HttpEvidence:
        """Fetch ``url`` and return the evidence bundle (never raises for I/O).

        Only ``http``/``https`` URLs are fetched. Any other scheme (including
        ``file://``, ``gopher://``) is refused so the fetcher can never be used
        as a local-file reader or SSRF primitive, regardless of caller.
        """
        timeout = timeout_s or _DEFAULT_TIMEOUT
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            return HttpEvidence(url=url)
        try:
            request = Request(url, headers={"User-Agent": self._user_agent})
            with urlopen(request, timeout=timeout) as response:  # nosec B310 - http/https only, scheme allow-list above
                status = getattr(response, "status", None)
                headers = {str(name).lower(): str(value) for name, value in response.headers.items()}
                try:
                    body = response.read(1_000_000).decode("utf-8", errors="replace")
                except OSError:
                    body = ""
        except Exception:  # noqa: BLE001 - fetch failures produce empty evidence
            return HttpEvidence(url=url, fetched_at=utcnow_iso())
        cookies = _parse_cookies(headers.get("set-cookie", ""))
        tls_subject, tls_issuer = _tls_metadata(url, timeout) if url.lower().startswith("https://") else ("", "")
        return HttpEvidence(
            url=url,
            status_code=status if isinstance(status, int) else None,
            headers=headers,
            html=body,
            cookies=cookies,
            title=_extract_title(body),
            meta=_extract_meta(body),
            scripts=_extract_scripts(body),
            tls_subject=tls_subject,
            tls_issuer=tls_issuer,
            redirect_target=str(headers.get("location", "")),
            fetched_at=utcnow_iso(),
        )


def _extract_title(body: str) -> str:
    """Extract the document title from an HTML body."""
    match = _TITLE_RE.search(body)
    if match is None:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:256]


def _extract_meta(body: str) -> dict[str, str]:
    """Extract name/property meta tags from an HTML body."""
    meta: dict[str, str] = {}
    for match in _META_RE.finditer(body):
        name = match.group(1).strip()
        if name and name not in meta:
            meta[name] = match.group(2).strip()
    return meta


def _extract_scripts(body: str) -> tuple[str, ...]:
    """Extract script ``src`` references from an HTML body."""
    return tuple(match for match in _SCRIPT_RE.findall(body) if match.strip())[:64]


def _parse_cookies(header: str) -> dict[str, str]:
    """Parse cookie name/value pairs from a ``Set-Cookie`` header."""
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if name and name not in cookies:
            cookies[name] = value.strip()
    return cookies


def _tls_metadata(url: str, timeout: float) -> tuple[str, str]:
    """Return the TLS certificate subject/issuer CNs for an HTTPS URL (best effort)."""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if not host:
            return "", ""
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw, context.wrap_socket(  # nosec B106
            raw, server_hostname=host
        ) as tls_socket:
            peer = tls_socket.getpeercert()
        if not peer:
            return "", ""
        subject = _cn(peer.get("subject"))
        issuer = _cn(peer.get("issuer"))
        return subject or "", issuer or ""
    except Exception:  # noqa: BLE001 - TLS metadata is best-effort
        return "", ""


def _cn(rdn: Any) -> str:
    """Extract the common name from an X.509 relative-distinguished-name list."""
    if not isinstance(rdn, (list, tuple)):
        return ""
    for item in rdn:
        if not isinstance(item, (list, tuple)):
            continue
        for field in item:
            if isinstance(field, (list, tuple)) and len(field) >= 2 and field[0] == "commonName":
                return str(field[1])
    return ""
