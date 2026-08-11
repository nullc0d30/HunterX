# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Web crawling tool adapters.

The integrated web crawling tool set: the in-process
:class:`~hunterx.tools.web.crawler.CrawlerAdapter` and the external
:class:`~hunterx.tools.web.katana.KatanaAdapter`. The registry and TIP
registration functions wire the set into the SDK engine and the Tool
Intelligence Platform.
"""

from hunterx.tools.web.base import WebToolAdapter
from hunterx.tools.web.crawler import CrawlerAdapter
from hunterx.tools.web.katana import KatanaAdapter
from hunterx.tools.web.registry import WEB_TOOL_IDS, register_web_adapters, web_adapters
from hunterx.tools.web.tip import register_web_tools, web_tool_specs
from hunterx.tools.web.url_discovery import (
    GauAdapter,
    GospiderAdapter,
    HakrawlerAdapter,
    UrlfinderAdapter,
    WaybackurlsAdapter,
)
from hunterx.tools.web.urlbase import UrlDiscoveryAdapter

__all__ = [
    "CrawlerAdapter",
    "GauAdapter",
    "GospiderAdapter",
    "HakrawlerAdapter",
    "KatanaAdapter",
    "UrlDiscoveryAdapter",
    "UrlfinderAdapter",
    "WEB_TOOL_IDS",
    "WaybackurlsAdapter",
    "WebToolAdapter",
    "register_web_adapters",
    "register_web_tools",
    "web_adapters",
    "web_tool_specs",
]
