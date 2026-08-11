# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the web crawling capability.

Exercises the full wiring through the assembled platform: the crawl service
and query service registered in the container, the crawling tools (crawler,
katana) available on the execution engine and TIP, and an end-to-end crawl run
over a scripted page map with persisted web intelligence and topology
integration.
"""

from __future__ import annotations

from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.domain.entities.tidb.web_crawl import URLObservation as TidbWebUrl
from hunterx.domain.entities.tidb.web_crawl import WebAPIEndpoint as TidbWebEndpoint
from hunterx.platform.assembler import build_platform
from hunterx.tools.web.httpclient import FetchedPage

_HOME_HTML = """<html><body>
<a href="/about">about</a>
<form action="/api/login" method="post"><input name="user"></form>
<a href="/api/v1/users?id=1">api</a>
<a href="wss://chat.acme.com/socket">chat</a>
</body></html>"""


def _pages() -> dict[str, FetchedPage]:
    return {
        "https://acme.com/": FetchedPage(
            url="https://acme.com/",
            status_code=200,
            content_type="text/html",
            content=_HOME_HTML,
        ),
        "https://acme.com/about": FetchedPage(
            url="https://acme.com/about",
            status_code=200,
            content_type="text/html",
            content="<a href='/'>home</a>",
        ),
        "https://acme.com/api/v1/users?id=1": FetchedPage(
            url="https://acme.com/api/v1/users?id=1",
            status_code=200,
            content_type="application/json",
            content="{}",
        ),
    }


class TestPlatformCrawl:
    def test_services_resolvable_from_platform(self) -> None:
        platform = build_platform()
        assert platform.crawl_service is not None
        assert platform.crawl_query_service is not None
        assert platform.has(type(platform.crawl_service))
        assert platform.resolve(type(platform.crawl_service)) is platform.crawl_service

    def test_tools_registered_on_engine_and_tip(self) -> None:
        platform = build_platform()
        for tool_id in ("crawler", "katana"):
            assert platform.execution_engine.adapter_for(tool_id) is not None
        ids = [tool.tool_id for tool in platform.tip.list_tools()]
        assert {"crawler", "katana"} <= set(ids)

    def test_end_to_end_crawl_roundtrip(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        pages = _pages()

        def fake_fetch(url: str, timeout: float) -> FetchedPage:
            return pages.get(
                url,
                FetchedPage(url=url, status_code=404, content_type="", error="not found"),
            )

        crawler = engine.adapter_for("crawler")
        crawler._fetch = fake_fetch  # noqa: SLF001
        engine.install_hook("crawler", lambda _tid, _version: "1.0.0")
        engine.install("crawler", version="1.0.0")

        batch = platform.crawl_service.run(
            mission_id="int-mission",
            target="https://acme.com/",
            mode="active",
            tools=["crawler"],
        )
        assert {u.url for u in batch.urls} == {
            "https://acme.com/",
            "https://acme.com/about",
            "https://acme.com/api/v1/users?id=1",
        }
        assert {(e.url, e.method.value) for e in batch.endpoints} == {
            ("https://acme.com/api/v1/users?id=1", "GET"),
            ("https://acme.com/api/login", "POST"),
        }
        assert [w.url for w in batch.websockets] == ["wss://chat.acme.com/socket"]

        assert platform.tidb.repository_for(TidbWebUrl).count() == 3
        assert platform.tidb.repository_for(TidbWebEndpoint).count() == 2
        assert platform.tidb.repository_for(TopologyRelationship).count() > 0

        assert len(platform.crawl_query_service.urls(mission_id="int-mission")) == 3
        assert (
            len(platform.crawl_query_service.endpoints(mission_id="int-mission")) == 2
        )
        assert platform.crawl_query_service.origins(mission_id="int-mission")[0]["key"] == (
            "https://acme.com"
        )
        executions = platform.crawl_query_service.executions(mission_id="int-mission")
        assert executions and executions[0]["mode"] == "active"
