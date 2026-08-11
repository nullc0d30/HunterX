# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Crawl execution policy.

A :class:`CrawlPolicy` bounds a crawl: what may be requested, how deep, how
fast and how much. Every mode ships a safe preset; the application layer never
raises limits above a preset without an explicit caller override, keeping the
capability respectful of the target's infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.web.models import HTTP_METHODS_DEFAULT


@dataclass(slots=True)
class CrawlPolicy:
    """Operational limits for one crawl run.

    Attributes:
        max_depth: maximum link depth from the seed.
        max_pages: maximum distinct pages to fetch.
        max_requests_per_host: per-host request ceiling.
        allowed_methods: HTTP methods the crawler may issue.
        allowed_content_types: response content types to parse for links
            (empty = parse anything text-like).
        follow_redirects: whether HTTP redirects are followed.
        max_redirects: per-URL redirect hop ceiling.
        timeout_seconds: per-request timeout.
        concurrency: worker count (active crawls only).
        rate_limit_per_second: request rate ceiling (0 = unlimited).
        user_agent: identifying user agent string.
        fetch_javascript: whether script sources are captured (not executed).
        respect_robots: honor robots.txt disallow rules.
        include_query: keep query strings when indexing URLs.
        mask_sensitive: redact sensitive parameter values in evidence.
        cache_ttl_seconds: how long fetched evidence stays cached.

    """

    max_depth: int = 3
    max_pages: int = 250
    max_requests_per_host: int = 2000
    allowed_methods: tuple[str, ...] = HTTP_METHODS_DEFAULT
    allowed_content_types: tuple[str, ...] = ()
    follow_redirects: bool = True
    max_redirects: int = 5
    timeout_seconds: float = 10.0
    concurrency: int = 2
    rate_limit_per_second: int = 0
    user_agent: str = "HunterX-WebCrawler/1.0 (security research; authorized targets only)"
    fetch_javascript: bool = True
    respect_robots: bool = True
    include_query: bool = True
    mask_sensitive: bool = True
    cache_ttl_seconds: int = 300

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe policy snapshot for run records."""
        return {
            "max_depth": self.max_depth,
            "max_pages": self.max_pages,
            "max_requests_per_host": self.max_requests_per_host,
            "allowed_methods": list(self.allowed_methods),
            "allowed_content_types": list(self.allowed_content_types),
            "follow_redirects": self.follow_redirects,
            "max_redirects": self.max_redirects,
            "timeout_seconds": self.timeout_seconds,
            "concurrency": self.concurrency,
            "rate_limit_per_second": self.rate_limit_per_second,
            "fetch_javascript": self.fetch_javascript,
            "respect_robots": self.respect_robots,
            "include_query": self.include_query,
            "mask_sensitive": self.mask_sensitive,
        }


#: Sensitive parameter names whose values are redacted in evidence.
SENSITIVE_PARAM_NAMES: tuple[str, ...] = (
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "pwd",
    "session",
    "sessionid",
    "sid",
    "auth",
    "authorization",
    "jwt",
    "cookie",
)


def mask_value(name: str, value: str) -> str:
    """Redact a sensitive parameter value, keeping the first character."""
    lowered = name.strip().lower()
    if lowered in SENSITIVE_PARAM_NAMES and value:
        return f"{value[:1]}****"
    return value
