# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Golden fixture tests for the certified toolchain (Sprint 034.5).

Every tool family is exercised against an authoritative fixture file so the
adapter/parser/normalizer contract is validated without any binary. Each row
asserts that the fixture parses into a non-empty canonical record set.
"""

from __future__ import annotations

from pathlib import Path

from tests.tools.conftest import FakeRunner, collect, make_context, payload_json
from tests.tools.test_adapters import (
    DirsearchAdapter,
    FeroxbusterAdapter,
    GauAdapter,
    GobusterAdapter,
    GospiderAdapter,
    HakrawlerAdapter,
    MassdnsAdapter,
    RustScanAdapter,
    SemgrepAdapter,
    ShufflednsAdapter,
    SQLmapAdapter,
    TrufflehogAdapter,
    WaybackurlsAdapter,
)

GOLDEN = Path(__file__).parent

#: tool → (adapter, fixture, parameter overrides)
_GOLDEN_ROWS = [
    ("massdns", MassdnsAdapter, "dns/massdns.jsonl", {}),
    ("shuffledns", ShufflednsAdapter, "dns/shuffledns.jsonl", {"wordlist": "/tmp/subs.txt"}),
    ("rustscan", RustScanAdapter, "livehost/rustscan.jsonl", {}),
    ("gau", GauAdapter, "web/gau.txt", {}),
    ("waybackurls", WaybackurlsAdapter, "web/waybackurls.txt", {}),
    ("gospider", GospiderAdapter, "web/gospider.jsonl", {}),
    ("hakrawler", HakrawlerAdapter, "web/hakrawler.txt", {}),
    ("gobuster", GobusterAdapter, "content/gobuster.jsonl", {"wordlist": "/tmp/words.txt"}),
    ("feroxbuster", FeroxbusterAdapter, "content/feroxbuster.jsonl", {"wordlist": "/tmp/words.txt"}),
    ("dirsearch", DirsearchAdapter, "content/dirsearch.json", {"wordlist": "/tmp/words.txt"}),
    ("sqlmap", SQLmapAdapter, "vuln/sqlmap.txt", {}),
    ("trufflehog", TrufflehogAdapter, "secrets/trufflehog.jsonl", {}),
    ("semgrep", SemgrepAdapter, "sast/semgrep.json", {}),
]

#: payload key that carries the canonical records per family.
_RECORD_KEYS = {
    "dns_records": {"massdns", "shuffledns"},
    "observations": {"rustscan"},
    "crawl": {"gau", "waybackurls", "gospider", "hakrawler"},
    "content": {"gobuster", "feroxbuster", "dirsearch"},
    "candidates": {"sqlmap", "semgrep"},
    "secrets": {"trufflehog"},
}


class TestGoldenToolchain:
    def test_every_fixture_parses_into_records(self):
        for tool_id, adapter_cls, fixture, params in _GOLDEN_ROWS:
            context = make_context(tool_id, target="example.com", params=params)
            adapter = adapter_cls(runner=FakeRunner(stdout=_read(fixture)))
            collector = collect(adapter, context)
            payload = payload_json(collector)
            key = _key_for(tool_id)
            records = payload[key]
            if key == "crawl":
                records = records["urls"]
            elif key == "content":
                records = records["requests"]
            elif key == "secrets":
                records = records["findings"]
            assert records, f"{tool_id}: fixture {fixture} produced no {key} records"

    def test_fixtures_are_non_empty_and_representative(self):
        for _, _, fixture, _ in _GOLDEN_ROWS:
            content = _read(fixture).strip()
            assert content, f"{fixture} is empty"


def _read(relative: str) -> str:
    return (GOLDEN / relative).read_text(encoding="utf-8")


def _key_for(tool_id: str) -> str:
    for key, tools in _RECORD_KEYS.items():
        if tool_id in tools:
            return key
    raise KeyError(tool_id)
