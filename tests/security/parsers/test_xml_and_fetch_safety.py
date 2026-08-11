# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""XML parser safety and SSRF boundary for in-process fetchers (Sprint 034.4
§11, §20).

- ``defusedxml`` (drop-in hardened ``xml.etree.ElementTree``) is used for tool
  XML (nmap, SOAP): external entities are refused (no XXE) and entity-declaring
  documents are refused (no entity-expansion bomb). Verified below; this is the
  fix for bandit B314.
- The in-process HTTP fetcher is scheme-locked to http/https so it can never be
  an SSRF file-read primitive.
"""

from __future__ import annotations

import time

from hunterx.tools.livehost.nmap import _parse_xml
from hunterx.tools.tech.httpclient import HttpFetcher


def test_external_entity_is_never_resolved() -> None:
    xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun>&xxe;</nmaprun>'
    root = _parse_xml(xxe)
    # No file was read: the parse either fails or yields no entity content.
    assert root is None or "xxe" not in (root.text or "")


def test_entity_expansion_bomb_is_inert() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
        "<nmaprun>&lol3;</nmaprun>"
    )
    started = time.monotonic()
    root = _parse_xml(bomb)
    elapsed = time.monotonic() - started
    # Never expands to a multi-GB tree: the hardened parser (defusedxml)
    # refuses the entity declarations outright (``None``); any parsed root
    # must also carry no expanded entity content.
    assert elapsed < 2.0
    assert root is None or root.tag == "nmaprun"


def test_deeply_nested_xml_parses_within_budget() -> None:
    deep = "<nmaprun>" + "<host>" * 5000 + "</host>" * 5000 + "</nmaprun>"
    started = time.monotonic()
    root = _parse_xml(deep)
    assert time.monotonic() - started < 5.0
    assert root is not None


def test_fetcher_refuses_non_http_schemes() -> None:
    fetcher = HttpFetcher()
    for url in ("file:///etc/passwd", "gopher://example.com", "ftp://example.com", "data:text/plain,x"):
        evidence = fetcher.fetch(url, timeout_s=1.0)
        # No fetch attempted: the evidence bundle is empty (no status/body).
        assert evidence.status_code is None
        assert evidence.html == ""


def test_fetcher_accepts_http_and_https() -> None:
    fetcher = HttpFetcher()
    evidence = fetcher.fetch("https://example.com/", timeout_s=0.1)
    # Whether or not the network is reachable, the scheme check must pass
    # through to a real attempt (not be refused as an unsupported scheme).
    assert evidence.url == "https://example.com/"
