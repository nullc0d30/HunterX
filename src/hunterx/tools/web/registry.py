# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web crawling tool adapter registry.

Builds and registers the web crawling adapters (in-process crawler and the
external Katana crawler) on an
:class:`~hunterx.tools.sdk.engine.ExecutionEngine`. This is the single place
that knows the web tool set, so callers (tests, the crawl service, the
platform) never construct individual adapters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.web.base import WebToolAdapter
from hunterx.tools.web.browser import BrowserTestingAdapter
from hunterx.tools.web.crawler import CrawlerAdapter
from hunterx.tools.web.httpclient import HttpPageFetcher, WebFetchFn
from hunterx.tools.web.katana import KatanaAdapter
from hunterx.tools.web.url_discovery import (
    GauAdapter,
    GospiderAdapter,
    HakrawlerAdapter,
    UrlfinderAdapter,
    WaybackurlsAdapter,
)

#: Canonical order and set of the integrated web crawling tools.
WEB_TOOL_IDS: tuple[str, ...] = (
    "crawler",
    "browser",
    "katana",
    "gospider",
    "hakrawler",
    "gau",
    "waybackurls",
    "urlfinder",
)


class WebAdapterFactory:
    """Instantiate the web crawling tool adapters."""

    def build(self, *, fetch: WebFetchFn | None = None) -> dict[str, WebToolAdapter]:
        """Return a fresh set of web adapters keyed by tool id.

        The ``fetch`` seam is shared with the in-process crawler; external
        crawlers run their own binary so they need no fetch seam.
        """
        crawler = CrawlerAdapter(fetch=fetch or HttpPageFetcher().fetch)
        return {
            "crawler": crawler,
            "browser": BrowserTestingAdapter(),
            "katana": KatanaAdapter(),
            "gospider": GospiderAdapter(),
            "hakrawler": HakrawlerAdapter(),
            "gau": GauAdapter(),
            "waybackurls": WaybackurlsAdapter(),
            "urlfinder": UrlfinderAdapter(),
        }

    def create(self, tool_id: str) -> WebToolAdapter:
        """Return a single adapter instance for ``tool_id``."""
        adapters = self.build()
        if tool_id not in adapters:
            raise KeyError(f"unknown web tool '{tool_id}'")
        return adapters[tool_id]


def web_adapters(*, fetch: WebFetchFn | None = None) -> dict[str, WebToolAdapter]:
    """Return a fresh mapping of web tool id to adapter instance."""
    return WebAdapterFactory().build(fetch=fetch)


def register_web_adapters(
    engine: ExecutionEngine,
    *,
    fetch: WebFetchFn | None = None,
) -> Mapping[str, WebToolAdapter]:
    """Register every web adapter on ``engine`` and return the mapping."""
    adapters = web_adapters(fetch=fetch)
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters
