# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""URL discovery and crawler adapters.

Integrates the URL discovery / passive-history crawlers used for attack-surface
collection: ``gau``, ``waybackurls``, ``urlfinder`` (passive/historical URL
collection) and ``gospider``, ``hakrawler`` (active lightweight crawlers).

All five invoke their external binary through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam and normalize JSONL or
plain-URL output into canonical :class:`URLObservation` instances. URLs are
data; malformed lines are skipped.
"""

from __future__ import annotations

import json

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.web.urlbase import UrlDiscoveryAdapter

_GAU_VERSION = "1.5.10"
_GOSPIDER_VERSION = "1.1.6"
_HAKRAWLER_VERSION = "2.1.0"
_WAYBACKURLS_VERSION = "0.1.0"
_URLFINDER_VERSION = "1.0.0"


class GauAdapter(UrlDiscoveryAdapter):
    """SDK adapter for ``gau`` — GetAllURLs passive URL collection."""

    source = "gau"

    descriptor = ToolDescriptor(
        name="gau",
        version=_GAU_VERSION,
        description="Passive URL collection from historical sources (wayback, otx, commoncrawl).",
        entrypoint="hunterx.tools.web.url_discovery:GauAdapter",
        targets=("domain",),
        capabilities=("historical-url-discovery", "endpoint-discovery"),
        permissions=("network",),
        parameters={
            "threads": {"type": "integer", "description": "Concurrent worker threads."},
            "subdomains": {"type": "boolean", "description": "Include subdomains of the target."},
            "providers": {"type": "array", "items": {"type": "string"}, "description": "Passive providers to query."},
            "filter_mime": {"type": "string", "description": "MIME types to exclude (comma-separated)."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["gau", context.target, "--threads", str(self._param_int(context, "threads", 10))]
        if self._param_bool(context, "subdomains", False):
            argv.append("--subs")
        providers = context.parameters.get("providers")
        if isinstance(providers, (list, tuple)) and providers:
            argv += ["--providers", ",".join(str(item) for item in providers)]
        filter_mime = context.parameters.get("filter_mime")
        if isinstance(filter_mime, str) and filter_mime:
            argv += ["--filter-mime-type", filter_mime]
        return argv

    def parse_lines(self, context: ExecutionContext, lines: list[str]) -> list[str]:
        """Parse lines."""
        return [_url_from_line(line) for line in lines]


class WaybackurlsAdapter(UrlDiscoveryAdapter):
    """SDK adapter for ``waybackurls`` — Wayback Machine URL collection."""

    source = "waybackurls"

    descriptor = ToolDescriptor(
        name="waybackurls",
        version=_WAYBACKURLS_VERSION,
        description="Fetch all known URLs for a domain from the Wayback Machine CDX API.",
        entrypoint="hunterx.tools.web.url_discovery:WaybackurlsAdapter",
        targets=("domain",),
        capabilities=("historical-url-discovery", "endpoint-discovery"),
        permissions=("network",),
        parameters={
            "dates": {"type": "boolean", "description": "Include timestamped snapshots."},
            "subdomains": {"type": "boolean", "description": "Include subdomains."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["waybackurls", context.target]
        if self._param_bool(context, "dates", False):
            argv.insert(1, "-dates")
        if self._param_bool(context, "subdomains", False):
            argv.insert(1, "-subs")
        return argv

    def parse_lines(self, context: ExecutionContext, lines: list[str]) -> list[str]:
        """Parse lines."""
        urls: list[str] = []
        for line in lines:
            if line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
        return urls


class UrlfinderAdapter(UrlDiscoveryAdapter):
    """SDK adapter for ``urlfinder`` — link and endpoint discovery from JS/content."""

    source = "urlfinder"

    descriptor = ToolDescriptor(
        name="urlfinder",
        version=_URLFINDER_VERSION,
        description="Discover URLs, endpoints and API references from web content and JavaScript.",
        entrypoint="hunterx.tools.web.url_discovery:UrlfinderAdapter",
        targets=("url", "host"),
        capabilities=("endpoint-discovery", "javascript-discovery"),
        permissions=("network",),
        parameters={
            "recursive": {"type": "boolean", "description": "Recursively crawl discovered content."},
            "max_depth": {"type": "integer", "description": "Maximum crawl depth."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["urlfinder", "-s", context.target]
        if self._param_bool(context, "recursive", False):
            argv.append("-r")
        depth = self._param_int(context, "max_depth", 0)
        if depth > 0:
            argv += ["-d", str(depth)]
        return argv

    def parse_lines(self, context: ExecutionContext, lines: list[str]) -> list[str]:
        """Parse lines."""
        urls: list[str] = []
        for line in lines:
            extracted = _url_from_line(line)
            if extracted:
                urls.append(extracted)
        return urls


class GospiderAdapter(UrlDiscoveryAdapter):
    """SDK adapter for ``gospider`` — fast active web crawler."""

    source = "gospider"

    descriptor = ToolDescriptor(
        name="gospider",
        version=_GOSPIDER_VERSION,
        description="Fast web crawler that collects URLs, subdomains, endpoints and files.",
        entrypoint="hunterx.tools.web.url_discovery:GospiderAdapter",
        targets=("url", "host", "domain"),
        capabilities=("web-crawling", "endpoint-discovery"),
        permissions=("network",),
        parameters={
            "depth": {"type": "integer", "description": "Maximum crawl depth."},
            "threads": {"type": "integer", "description": "Concurrent crawler threads."},
            "include_subdomains": {"type": "boolean", "description": "Crawl discovered subdomains."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["gospider", "-s", context.target, "--json"]
        depth = self._param_int(context, "depth", 3)
        if depth > 0:
            argv += ["-d", str(depth)]
        threads = self._param_int(context, "threads", 0)
        if threads > 0:
            argv += ["-c", str(threads)]
        if self._param_bool(context, "include_subdomains", False):
            argv.append("--include-subs")
        return argv

    def parse_lines(self, context: ExecutionContext, lines: list[str]) -> list[str]:
        """Parse lines."""
        urls: list[str] = []
        for line in lines:
            if line.startswith("{"):
                extracted = _json_url(line)
                if extracted:
                    urls.append(extracted)
            elif line.startswith("http://") or line.startswith("https://"):
                urls.append(line)
        return urls


class HakrawlerAdapter(UrlDiscoveryAdapter):
    """SDK adapter for ``hakrawler`` — simple lightweight crawler."""

    source = "hakrawler"

    descriptor = ToolDescriptor(
        name="hakrawler",
        version=_HAKRAWLER_VERSION,
        description="Simple, fast web crawler designed for quick and easy discovery of endpoints.",
        entrypoint="hunterx.tools.web.url_discovery:HakrawlerAdapter",
        targets=("url", "host", "domain"),
        capabilities=("web-crawling", "endpoint-discovery"),
        permissions=("network",),
        parameters={
            "depth": {"type": "integer", "description": "Maximum crawl depth."},
            "plain": {"type": "boolean", "description": "Only output URLs (no status codes)."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["hakrawler", "-url", context.target]
        depth = self._param_int(context, "depth", 2)
        if depth > 0:
            argv += ["-depth", str(depth)]
        if self._param_bool(context, "plain", True):
            argv.append("-plain")
        return argv

    def parse_lines(self, context: ExecutionContext, lines: list[str]) -> list[str]:
        """Parse lines."""
        urls: list[str] = []
        for line in lines:
            for token in line.split():
                if token.startswith("http://") or token.startswith("https://"):
                    urls.append(token)
                    break
        return urls


def _url_from_line(line: str) -> str:
    """Return a URL from a JSONL or plain line, or ``""``."""
    line = line.strip().strip('"\'`')
    if line.startswith("{"):
        return _json_url(line)
    if line.startswith("http://") or line.startswith("https://"):
        return line
    return ""


def _json_url(line: str) -> str:
    """Extract a URL from a JSON object line."""
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return ""
    if not isinstance(payload, dict):
        return ""
    for key in ("url", "URL", "endpoint", "href", "request"):
        value = payload.get(key)
        if isinstance(value, str) and (value.startswith("http://") or value.startswith("https://")):
            return value
    return ""


__all__ = ["GauAdapter", "WaybackurlsAdapter", "UrlfinderAdapter", "GospiderAdapter", "HakrawlerAdapter"]
