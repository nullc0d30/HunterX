# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process web crawler adapter.

The binary-free crawling path. The adapter walks a bounded, in-scope crawl of
the target: it fetches pages through the injectable :data:`WebFetchFn` seam,
follows links up to a depth ceiling, records redirects, and runs the domain
parsers over each page to discover API/WebSocket/GraphQL endpoints and
authentication boundaries. It emits canonical crawl observations as a JSON
payload under the ``crawl`` key.

Scope is enforced by :class:`~hunterx.domain.web.scope.WebScopeEnforcer`
built from execution parameters and is fail-closed: with no roots configured
nothing is fetched. Redirect targets and discovered infrastructure are
recorded as observations but never fetched out of scope.
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import replace
from typing import TypeVar

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.web.models import (
    APIEndpoint,
    AuthenticationBoundary,
    CrawlEvidence,
    GraphQLEndpoint,
    Redirect,
    URLObservation,
    WebSocketEndpoint,
    _http_method,
)
from hunterx.domain.web.parsers import (
    build_api_endpoint,
    detect_api_urls,
    detect_auth_boundary,
    detect_graphql,
    detect_websocket_headers,
    detect_websocket_urls,
    extract_forms,
    extract_links,
    parameter_names,
    parse_robots,
    should_parse_content_type,
)
from hunterx.domain.web.scope import WebScopeEnforcer, WebScopePolicy
from hunterx.domain.web.urls import URLNormalizer
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.web.base import WebToolAdapter
from hunterx.tools.web.httpclient import FetchedPage, HttpPageFetcher, WebFetchFn

_VERSION = "1.0.0"

#: Any observation type carrying provenance fields.
_Observed = TypeVar(
    "_Observed",
    APIEndpoint,
    WebSocketEndpoint,
    GraphQLEndpoint,
    AuthenticationBoundary,
    Redirect,
)


class CrawlerAdapter(WebToolAdapter):
    """SDK adapter performing bounded, in-scope web crawling in-process."""

    descriptor = ToolDescriptor(
        name="crawler",
        version=_VERSION,
        description="In-process bounded web crawler producing canonical crawl observations.",
        entrypoint="hunterx.tools.web.crawler:CrawlerAdapter",
        targets=("url", "host", "domain"),
        capabilities=("web-crawling", "web-discovery"),
        permissions=("network",),
        parameters={
            "seed_urls": {
                "type": "array",
                "description": "Explicit seed URLs to crawl (overrides the target).",
            },
            "depth": {"type": "integer", "description": "Maximum crawl depth from a seed."},
            "max_pages": {
                "type": "integer",
                "description": "Maximum number of pages to fetch in one run.",
            },
            "scope_roots": {
                "type": "array",
                "description": "Authorized hosts/domains; empty means fail-closed.",
            },
            "follow_subdomains": {"type": "boolean", "description": "Crawl subdomains of roots."},
            "excluded_extensions": {
                "type": "array",
                "description": "File extensions never fetched.",
            },
            "respect_robots": {"type": "boolean", "description": "Honor robots.txt in the crawl."},
            "timeout": {"type": "number", "description": "Per-fetch timeout in seconds."},
        },
    )

    def __init__(
        self,
        fetch: WebFetchFn | None = None,
        normalizer: URLNormalizer | None = None,
    ) -> None:
        self._fetch = fetch or HttpPageFetcher().fetch
        self._normalizer = normalizer or URLNormalizer()

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Crawl the target and emit canonical crawl observations."""
        scope = self._build_scope(context)
        seeds = self._seeds(context)
        timeout = self._optional_float(context.parameters.get("timeout"), 10.0)
        max_pages = self._param_int(context, "max_pages", 100)
        respect_robots = self._param_bool(context, "respect_robots", True)

        if not scope.policy.is_empty():
            seeds = [url for url in seeds if scope.decides(url).allowed]
        if not seeds:
            collector.set_exit_code(0)
            collector.attach_stderr("no in-scope seeds to crawl")
            self.emit(collector)
            return

        crawled: dict[str, URLObservation] = {}
        redirects: list[Redirect] = []
        endpoints: list[APIEndpoint] = []
        websockets: list[WebSocketEndpoint] = []
        graphqls: list[GraphQLEndpoint] = []
        auth_boundaries: list[AuthenticationBoundary] = []
        evidence: list[CrawlEvidence] = []
        visited: set[str] = set()
        robots_disallow: tuple[str, ...] = ()

        queue: deque[tuple[str, int]] = deque((url, 0) for url in seeds)
        if respect_robots and not scope.policy.is_empty():
            robots_url = self._robots_url(context.target)
            if scope.decides(robots_url).allowed:
                page = self._fetch_page(robots_url, timeout, context)
                evidence.append(
                    self._evidence(robots_url, "robots", page.content[:2000], context)
                )
                robots_disallow = tuple(parse_robots(page.content).get("disallow", ()))

        while queue and len(crawled) < max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            if self._blocked_by_robots(url, robots_disallow):
                continue
            page = self._fetch_page(url, timeout, context)
            self._record_page(crawled, url, page, context)
            if page.error:
                evidence.append(self._evidence(url, "response", page.error, context))
            if page.is_redirect:
                redirects.append(self._make_redirect(url, page, context))
                target = self._resolve_redirect_target(url, page)
                if target and scope.decides(target, depth=depth + 1).allowed:
                    queue.append((target, depth + 1))
                continue
            boundary = detect_auth_boundary(
                url,
                status_code=page.status_code,
                headers=page.headers,
                html=page.content,
                normalizer=self._normalizer,
            )
            if boundary is not None:
                auth_boundaries.append(self._tag(boundary, url, context))
            if detect_websocket_headers(page.headers):
                ws_url = self._websocket_url(url)
                websockets.append(
                    self._tag(WebSocketEndpoint(url=ws_url), url, context)
                )
            for raw_ws in detect_websocket_urls(page.content):
                try:
                    ws = self._normalizer.normalize(raw_ws)
                    ws_host = self._normalizer.host(ws)
                except ValueError:
                    continue
                if scope.policy.is_empty() or scope.allows_host(ws_host) or scope.allows_ip(ws_host):
                    websockets.append(self._tag(WebSocketEndpoint(url=ws), ws, context))
            if should_parse_content_type(page.content_type):
                for api_url in detect_api_urls(
                    page.content, url, self._normalizer, content_type=page.content_type
                ):
                    if scope.decides(api_url).allowed:
                        params = tuple({"name": name} for name in parameter_names(api_url))
                        endpoints.append(
                            self._tag(
                                build_api_endpoint(
                                    api_url,
                                    response_content_type=page.content_type,
                                    parameters=params,
                                    evidence=({"fragment": "html"},),
                                ),
                                api_url,
                                context,
                            )
                        )
                for form in extract_forms(page.content, url, self._normalizer):
                    action = form.get("action")
                    if not action:
                        continue
                    method = str(form.get("method") or "GET")
                    fields = form.get("fields") or []
                    params = tuple({"name": field.get("name")} for field in fields if field.get("name"))
                    endpoints.append(
                        self._tag(
                            build_api_endpoint(
                                action,
                                method=method,
                                parameters=params,
                                evidence=({"fragment": "form"},),
                            ),
                            action,
                            context,
                        )
                    )
            if detect_graphql(url, page.content_type):
                graphqls.append(
                    self._tag(GraphQLEndpoint(url=url, methods=("POST", "GET")), url, context)
                )
            evidence.append(self._evidence(url, "html", page.content[:2000], context))
            for raw_link in extract_links(page.content, url, self._normalizer):
                try:
                    link = self._normalizer.normalize(raw_link, base=url)
                except ValueError:
                    continue
                if link in visited:
                    continue
                decision = scope.decides(link, depth=depth + 1)
                if decision.allowed and decision.in_scope_host:
                    queue.append((link, depth + 1))

        self.emit(
            collector,
            urls=list(crawled.values()),
            redirects=redirects,
            endpoints=endpoints,
            websockets=websockets,
            graphqls=graphqls,
            auth_boundaries=auth_boundaries,
            evidence=evidence,
        )
        collector.set_exit_code(0)

    # -- crawl internals ------------------------------------------------------

    def _build_scope(self, context: ExecutionContext) -> WebScopeEnforcer:
        """Build a fail-closed scope policy from execution parameters."""
        roots = context.parameters.get("scope_roots")
        if not isinstance(roots, (list, tuple)) or not roots:
            roots = self._seed_roots(context)
        policy = WebScopePolicy(
            roots=tuple(str(item) for item in roots if str(item).strip()),
            excluded_extensions=tuple(
                str(item) for item in (context.parameters.get("excluded_extensions") or ())
            ),
            max_depth=self._param_int(context, "depth", 3),
            follow_subdomains=self._param_bool(context, "follow_subdomains", True),
            respect_robots=self._param_bool(context, "respect_robots", True),
        )
        return WebScopeEnforcer(policy)

    def _seeds(self, context: ExecutionContext) -> list[str]:
        """Resolve the crawl seed URLs from parameters or the target."""
        seeds = context.parameters.get("seed_urls")
        if isinstance(seeds, (list, tuple)) and seeds:
            resolved: list[str] = []
            for seed in seeds:
                try:
                    resolved.append(self._normalizer.normalize(str(seed)))
                except ValueError:
                    continue
            return resolved
        return self._target_seeds(context)

    def _target_seeds(self, context: ExecutionContext) -> list[str]:
        """Build seed URLs from the execution target."""
        target = context.target.strip()
        if target.lower().startswith(("http://", "https://")):
            try:
                return [self._normalizer.normalize(target)]
            except ValueError:
                return []
        seeds: list[str] = []
        for scheme in ("https", "http"):
            try:
                seeds.append(self._normalizer.normalize(f"{scheme}://{target}/"))
            except ValueError:
                continue
        return seeds

    def _seed_roots(self, context: ExecutionContext) -> list[str]:
        """Derive scope roots from the target when no explicit roots are set."""
        target = context.target.strip()
        if target.lower().startswith(("http://", "https://")):
            try:
                return [self._normalizer.host(target)]
            except ValueError:
                return [target]
        return [target]

    def _fetch_page(self, url: str, timeout: float, context: ExecutionContext) -> FetchedPage:
        """Fetch ``url`` through the injectable seam, never raising."""
        try:
            return self._fetch(url, timeout)
        except Exception as exc:  # noqa: BLE001 - fetch failures become empty pages
            return FetchedPage(url=url, error=f"fetch failed: {exc}", fetched_at=self._now())

    def _record_page(
        self,
        crawled: dict[str, URLObservation],
        url: str,
        page: FetchedPage,
        context: ExecutionContext,
    ) -> None:
        """Record the URL observation for a fetched page."""
        try:
            parsed = self._normalizer.parse(url)
        except ValueError:
            return
        key = f"GET:{url}"
        if key not in crawled:
            crawled[key] = URLObservation(
                url=url,
                method=_http_method("GET"),
                origin=parsed.origin,
                path=parsed.path,
                query=parsed.query,
                status_code=page.status_code if page.status_code else None,
                content_type=page.content_type or None,
                source="crawl",
                tool_id="crawler",
                target_key=self._target_key(context, url),
                correlation_id=context.correlation_id,
                mission_id=context.mission_id,
                execution_id=context.execution_id,
            )

    def _make_redirect(self, url: str, page: FetchedPage, context: ExecutionContext) -> Redirect:
        """Build a :class:`Redirect` observation for a fetched redirect page."""
        redirect_type = "permanent" if page.status_code in (301, 308) else "temporary"
        return self._tag(
            Redirect(
                source_url=url,
                destination_url=page.redirect_url,
                status_code=page.status_code,
                redirect_type=redirect_type,
                chain=(url, page.redirect_url),
            ),
            url,
            context,
        )

    def _resolve_redirect_target(self, url: str, page: FetchedPage) -> str | None:
        """Resolve a redirect ``Location`` to a canonical URL (``None`` when bad)."""
        try:
            return self._normalizer.normalize(page.redirect_url, base=url)
        except ValueError:
            return None

    def _websocket_url(self, url: str) -> str:
        """Derive a WebSocket URL from an HTTP(S) page URL."""
        lowered = url.lower()
        if lowered.startswith("https://"):
            return "wss://" + url[len("https://") :]
        if lowered.startswith("http://"):
            return "ws://" + url[len("http://") :]
        return url

    def _robots_url(self, target: str) -> str:
        """Build the robots.txt URL for a target."""
        try:
            parsed = self._normalizer.parse(target)
        except ValueError:
            parsed = self._normalizer.parse("https://" + target)
        return f"{parsed.origin}/robots.txt"

    def _blocked_by_robots(self, url: str, disallow: tuple[str, ...]) -> bool:
        """Return ``True`` when a URL matches a robots.txt ``Disallow`` rule."""
        path = url.split("?", 1)[0].split("#", 1)[0]
        return any((rule == "/" or path.startswith(rule)) for rule in disallow if rule)

    def _evidence(
        self, url: str, evidence_type: str, value: str, context: ExecutionContext
    ) -> CrawlEvidence:
        """Build a :class:`CrawlEvidence` record with a content hash."""
        integrity = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
        return CrawlEvidence(
            url=url,
            evidence_type=evidence_type,
            value=value[:4000],
            source="crawl",
            tool_id="crawler",
            integrity=integrity,
            target_key=self._target_key(context, url),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
        )

    def _tag(self, observation: _Observed, url: str, context: ExecutionContext) -> _Observed:
        """Stamp provenance fields onto an observation."""
        return replace(
            observation,
            tool_id="crawler",
            source="crawl",
            target_key=self._target_key(context, url),
            correlation_id=context.correlation_id,
            mission_id=context.mission_id,
        )

    # -- parameter helpers ----------------------------------------------------

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = context.parameters.get(name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        try:
            return int(context.parameters.get(name, default))
        except (TypeError, ValueError):
            return default

    def _optional_float(self, value: object, default: float) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(str(value))
        except (TypeError, ValueError):
            return default

    def _now(self) -> str:
        from hunterx.shared.time import utcnow_iso

        return utcnow_iso()
