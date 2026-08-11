# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Crawl strategy selection.

A :class:`CrawlStrategy` is the pure decision of which tools run for a given
mode and target kind, plus the :class:`CrawlPolicy` bounds. Like the
technology-fingerprinting strategy it fails closed: passive modes run no tools,
and unknown tool ids are never selected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.web.models import WebCrawlMode
from hunterx.domain.web.policy import CrawlPolicy

#: Canonical tool ids registered by the web crawling adapters.
WEB_TOOL_IDS: tuple[str, ...] = ("crawler", "katana")

#: Target kinds a crawl can be launched against.
_SUPPORTED_TARGET_KINDS = frozenset({"url", "host", "domain", "ip"})


@dataclass(frozen=True, slots=True)
class CrawlStrategy:
    """Selected tooling and bounds for one crawl run.

    Attributes:
        mode: the crawl mode.
        target_kind: canonical target kind.
        tools: ordered tool ids to run through the execution engine.
        policy: the :class:`CrawlPolicy` bounds the run.
        fetch_robots: whether robots.txt is fetched in this mode.
        fetch_sitemap: whether sitemap.xml is fetched in this mode.
        incremental: whether only new/changed resources are retained.
        api_focused: whether API surfaces are prioritized.

    """

    mode: WebCrawlMode
    target_kind: str
    tools: tuple[str, ...]
    policy: CrawlPolicy = field(default_factory=CrawlPolicy)
    fetch_robots: bool = False
    fetch_sitemap: bool = False
    incremental: bool = False
    api_focused: bool = False


class CrawlStrategyBuilder:
    """Build the strategy for a crawl run from mode and target."""

    def build(
        self,
        target: str,
        *,
        mode: WebCrawlMode | str,
        target_kind: str,
        tools: tuple[str, ...] = (),
        max_depth: int | None = None,
        max_pages: int | None = None,
        max_concurrency: int = 2,
        with_incremental: bool = False,
        with_browser: bool = False,
    ) -> CrawlStrategy:
        """Return the strategy for a crawl run.

        Raises:
            ValueError: when the mode is unknown or the target kind is
                unsupported.

        """
        crawl_mode = WebCrawlMode(mode if isinstance(mode, str) else mode.value)
        if target_kind not in _SUPPORTED_TARGET_KINDS:
            raise ValueError(f"unsupported crawl target kind '{target_kind}'")
        policy = _policy_for(crawl_mode, max_depth=max_depth, max_pages=max_pages, max_concurrency=max_concurrency)
        tools_selected = tuple(tool_id for tool_id in tools if tool_id in WEB_TOOL_IDS) if tools else ()
        strategy = CrawlStrategy(
            mode=crawl_mode,
            target_kind=target_kind,
            tools=tools_selected,
            policy=policy,
            incremental=with_incremental or crawl_mode is WebCrawlMode.INCREMENTAL,
        )
        if crawl_mode in (WebCrawlMode.SITEMAP, WebCrawlMode.ACTIVE):
            strategy = _with(snapshot=strategy, fetch_sitemap=True)
        if crawl_mode in (WebCrawlMode.ROBOTS, WebCrawlMode.ACTIVE, WebCrawlMode.BROWSER):
            strategy = _with(snapshot=strategy, fetch_robots=True)
        if crawl_mode is WebCrawlMode.API:
            strategy = _with(snapshot=strategy, api_focused=True)
        if with_browser or crawl_mode is WebCrawlMode.BROWSER:
            strategy = _with(
                snapshot=strategy,
                tools=("katana",) if not strategy.tools else strategy.tools,
                fetch_javascript=True,
            )
        return strategy

    def default_tools(self, mode: WebCrawlMode) -> tuple[str, ...]:
        """Return the default tool set for ``mode`` (empty for passive modes)."""
        if mode in (WebCrawlMode.PASSIVE, WebCrawlMode.HISTORICAL):
            return ()
        return WEB_TOOL_IDS


def _policy_for(
    mode: WebCrawlMode,
    *,
    max_depth: int | None,
    max_pages: int | None,
    max_concurrency: int,
) -> CrawlPolicy:
    """Build a mode-appropriate policy without ever exceeding callers' bounds."""
    base = CrawlPolicy()
    if mode is WebCrawlMode.PASSIVE:
        base = CrawlPolicy(max_depth=0, max_pages=0, concurrency=0, fetch_javascript=False, follow_redirects=False)
    elif mode is WebCrawlMode.TARGETED:
        base = CrawlPolicy(max_depth=1, max_pages=20)
    elif mode in (WebCrawlMode.SITEMAP, WebCrawlMode.ROBOTS):
        base = CrawlPolicy(max_depth=0, max_pages=50, fetch_javascript=False)
    elif mode is WebCrawlMode.API:
        base = CrawlPolicy(max_depth=2, max_pages=100)
    elif mode is WebCrawlMode.HISTORICAL:
        base = CrawlPolicy(max_depth=0, max_pages=0, concurrency=0)
    elif mode is WebCrawlMode.BROWSER:
        base = CrawlPolicy(max_depth=3, max_pages=100, fetch_javascript=True)
    base.max_depth = max_depth if max_depth is not None else base.max_depth
    base.max_pages = max_pages if max_pages is not None else base.max_pages
    base.concurrency = max(1, min(max_concurrency, base.max_depth or 1) or 1) if mode not in (
        WebCrawlMode.PASSIVE,
        WebCrawlMode.HISTORICAL,
    ) else 0
    return base


def _with(snapshot: CrawlStrategy, **overrides: Any) -> CrawlStrategy:
    """Return a copy of ``snapshot`` with fields overridden."""
    from dataclasses import replace

    return replace(snapshot, **overrides)
