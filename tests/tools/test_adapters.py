# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adapter argv/parser contract tests for the certified toolchain.

Every subprocess-backed adapter is exercised with a fake runner fed an
authoritative fixture. Execution-dependent validation (real binaries) is
explicitly out of scope here and marked with the ``tools`` marker in the
integration suite; these tests certify the adapter contract (structured argv
and canonical parsers) without any binary.
"""

from __future__ import annotations

import pytest

from hunterx.tools.content.bruteforcers import (
    DirsearchAdapter,
    FeroxbusterAdapter,
    GobusterAdapter,
)
from hunterx.tools.dns.massdns import MassdnsAdapter
from hunterx.tools.dns.shuffledns import ShufflednsAdapter
from hunterx.tools.exploit.adapters import (
    ExploitdbAdapter,
    MetasploitAdapter,
    SearchsploitAdapter,
)
from hunterx.tools.javascript.external import (
    LinkFinderAdapter,
    SecretFinderAdapter,
    XnLinkFinderAdapter,
)
from hunterx.tools.livehost.rustscan import RustScanAdapter
from hunterx.tools.parameter.adapters import ArjunAdapter, KiterunnerAdapter, ParamspiderAdapter
from hunterx.tools.proxy.adapters import MitmproxyAdapter, ZapAdapter
from hunterx.tools.sast.semgrep import SemgrepAdapter
from hunterx.tools.secrets.trufflehog import TrufflehogAdapter
from hunterx.tools.vuln.injection import (
    CommixAdapter,
    DalfoxAdapter,
    GhauriAdapter,
    InteractshAdapter,
    SQLmapAdapter,
    SSTImapAdapter,
    TplmapAdapter,
    XSStrikeAdapter,
    XXEinjectorAdapter,
)
from hunterx.tools.web.url_discovery import (
    GauAdapter,
    GospiderAdapter,
    HakrawlerAdapter,
    UrlfinderAdapter,
    WaybackurlsAdapter,
)

from .conftest import FakeRunner, collect, make_context, payload_json


class TestDnsAdapters:
    def test_massdns_argv_and_parse(self, golden_text):
        context = make_context("massdns")
        adapter = MassdnsAdapter(runner=FakeRunner(stdout=golden_text("dns/massdns.jsonl")))
        collector = collect(adapter, context)
        records = payload_json(collector)["dns_records"]
        assert len(records) == 3
        assert adapter.runner.calls[0][0] == "massdns"
        assert "-o" in adapter.runner.calls[0] and "J" in adapter.runner.calls[0]

    def test_massdns_empty_is_valid(self, golden_text):
        adapter = MassdnsAdapter(runner=FakeRunner(stdout=golden_text("dns/massdns_empty.jsonl")))
        collector = collect(adapter, make_context("massdns"))
        assert payload_json(collector)["count"] == 0

    def test_shuffledns_argv_and_parse(self, golden_text):
        context = make_context("shuffledns", params={"wordlist": "/tmp/subs.txt", "resolvers": "8.8.8.8"})
        adapter = ShufflednsAdapter(runner=FakeRunner(stdout=golden_text("dns/shuffledns.jsonl")))
        collector = collect(adapter, context)
        records = payload_json(collector)["dns_records"]
        assert {record["name"] for record in records} == {"api.example.com", "dev.example.com"}
        assert adapter.runner.calls[0][1] == "-d"

    def test_shuffledns_requires_wordlist(self):
        adapter = ShufflednsAdapter(runner=FakeRunner())
        with pytest.raises(ValueError):
            adapter.build_argv(make_context("shuffledns"))


class TestLivehostAdapters:
    def test_rustscan_argv_and_parse(self, golden_text):
        context = make_context("rustscan", target="10.0.0.1")
        adapter = RustScanAdapter(runner=FakeRunner(stdout=golden_text("livehost/rustscan.jsonl")))
        collector = collect(adapter, context)
        observations = payload_json(collector)["observations"]
        ports = [obs["port"] for obs in observations if obs.get("type") == "port"]
        assert set(ports) == {80, 443}


class TestWebAdapters:
    @pytest.mark.parametrize(
        ("tool", "fixture", "expected"),
        [
            ("gau", "web/gau.txt", {"https://example.com/admin", "https://example.com/api/users?id=1", "https://example.com/login"}),
            ("waybackurls", "web/waybackurls.txt", {"https://example.com/old-path", "https://example.com/assets/app.js"}),
            ("urlfinder", "web/urlfinder.txt", {"https://example.com/api/v1/users", "https://example.com/assets/script.js"}),
            ("hakrawler", "web/hakrawler.txt", {"https://example.com/home", "https://example.com/about"}),
        ],
    )
    def test_url_tools(self, golden_text, tool, fixture, expected):
        adapter = {"gau": GauAdapter, "waybackurls": WaybackurlsAdapter, "urlfinder": UrlfinderAdapter, "hakrawler": HakrawlerAdapter}[tool](
            runner=FakeRunner(stdout=golden_text(fixture))
        )
        collector = collect(adapter, make_context(tool))
        urls = {entry["url"] for entry in payload_json(collector)["crawl"]["urls"]}
        assert urls == expected

    def test_gospider_jsonl(self, golden_text):
        adapter = GospiderAdapter(runner=FakeRunner(stdout=golden_text("web/gospider.jsonl")))
        collector = collect(adapter, make_context("gospider", target="https://example.com"))
        urls = {entry["url"] for entry in payload_json(collector)["crawl"]["urls"]}
        assert {"https://example.com/index", "https://example.com/contact"} <= urls


class TestContentAdapters:
    def test_gobuster(self, golden_text):
        context = make_context("gobuster", params={"wordlist": "/tmp/words.txt"})
        adapter = GobusterAdapter(runner=FakeRunner(stdout=golden_text("content/gobuster.jsonl")))
        collector = collect(adapter, context)
        records = payload_json(collector)["content"]["requests"]
        assert {record["url"] for record in records} == {"/admin", "/login"}
        assert adapter.runner.calls[0][1] == "dir"

    def test_feroxbuster(self, golden_text):
        context = make_context("feroxbuster", params={"wordlist": "/tmp/words.txt"})
        adapter = FeroxbusterAdapter(runner=FakeRunner(stdout=golden_text("content/feroxbuster.jsonl")))
        collector = collect(adapter, context)
        records = payload_json(collector)["content"]["requests"]
        assert records[0]["url"] == "https://example.com/admin"

    def test_dirsearch(self, golden_text):
        context = make_context("dirsearch", params={"wordlist": "/tmp/words.txt"})
        adapter = DirsearchAdapter(runner=FakeRunner(stdout=golden_text("content/dirsearch.json")))
        collector = collect(adapter, context)
        records = payload_json(collector)["content"]["requests"]
        assert records[0]["status"] == 200

    @pytest.mark.parametrize(
        "tool", ["gobuster", "feroxbuster", "dirsearch"],
    )
    def test_requires_wordlist(self, tool):
        adapter = {"gobuster": GobusterAdapter, "feroxbuster": FeroxbusterAdapter, "dirsearch": DirsearchAdapter}[tool](
            runner=FakeRunner()
        )
        with pytest.raises(ValueError):
            adapter.build_argv(make_context(tool))


class TestParameterAdapters:
    def test_arjun(self, golden_text):
        adapter = ArjunAdapter(runner=FakeRunner(stdout=golden_text("parameter/arjun.json")))
        collector = collect(adapter, make_context("arjun", target="https://example.com"))
        findings = payload_json(collector)["parameters"]["findings"]
        names = {finding["name"] for finding in findings}
        assert names == {"id", "page"}

    def test_paramspider(self, golden_text):
        adapter = ParamspiderAdapter(runner=FakeRunner(stdout=golden_text("parameter/paramspider.txt")))
        collector = collect(adapter, make_context("paramspider", target="example.com"))
        findings = payload_json(collector)["parameters"]["findings"]
        names = {finding["name"] for finding in findings}
        assert {"q", "page", "category"} <= names

    def test_kiterunner(self, golden_text):
        context = make_context("kiterunner", params={"wordlist": "/tmp/routes.txt"})
        adapter = KiterunnerAdapter(runner=FakeRunner(stdout=golden_text("parameter/kiterunner.jsonl")))
        collector = collect(adapter, context)
        findings = payload_json(collector)["parameters"]["findings"]
        assert findings[0]["endpoint"] == "https://example.com/api/users"


class TestJavascriptAdapters:
    def test_linkfinder(self, golden_text):
        adapter = LinkFinderAdapter(runner=FakeRunner(stdout=golden_text("javascript/linkfinder.txt")))
        collector = collect(adapter, make_context("linkfinder", target="https://example.com/app.js"))
        observations = payload_json(collector)["observations"]
        assert observations[0]["kind"] == "endpoint"

    def test_secretfinder_redacts(self, golden_text):
        adapter = SecretFinderAdapter(runner=FakeRunner(stdout=golden_text("javascript/secretfinder.json")))
        collector = collect(adapter, make_context("secretfinder", target="https://example.com/app.js"))
        observations = payload_json(collector)["observations"]
        secrets = [obs for obs in observations if obs["kind"] == "secret"]
        assert secrets
        assert "AKIA1234" not in secrets[0]["value"]

    def test_xnlinkfinder(self, golden_text):
        adapter = XnLinkFinderAdapter(runner=FakeRunner(stdout=golden_text("javascript/xnlinkfinder.txt")))
        collector = collect(adapter, make_context("xnlinkfinder", target="https://example.com/app.js"))
        observations = payload_json(collector)["observations"]
        assert any(obs["kind"] == "endpoint" for obs in observations)


class TestVulnerabilityAdapters:
    @pytest.mark.parametrize(
        ("adapter_cls", "fixture", "vuln_class", "params"),
        [
            (DalfoxAdapter, "vuln/dalfox.json", "xss", None),
            (XSStrikeAdapter, "vuln/xssstrike.txt", "xss", None),
            (SQLmapAdapter, "vuln/sqlmap.txt", "sql-injection", None),
            (GhauriAdapter, "vuln/ghauri.txt", "sql-injection", None),
            (CommixAdapter, "vuln/commix.txt", "command-injection", None),
            (TplmapAdapter, "vuln/tplmap.txt", "ssti", None),
            (SSTImapAdapter, "vuln/sstimap.txt", "ssti", None),
            (XXEinjectorAdapter, "vuln/xxeinjector.txt", "xxe", {"file": "/tmp/payloads.txt"}),
        ],
    )
    def test_injection_candidates_are_validated(self, golden_text, adapter_cls, fixture, vuln_class, params):
        context = make_context("vuln-test", target="https://example.com/", params=params)
        adapter = adapter_cls(runner=FakeRunner(stdout=golden_text(fixture)))
        collector = collect(adapter, context)
        candidates = payload_json(collector)["candidates"]
        assert candidates, f"{adapter_cls.__name__} produced no candidates"
        for candidate in candidates:
            assert candidate["requires_validation"] is True
            assert candidate["vulnerability_class"] == vuln_class

    def test_interactsh_acquires_oaast_domain(self, golden_text):
        adapter = InteractshAdapter(runner=FakeRunner(stdout=golden_text("vuln/interactsh.txt")))
        collector = collect(adapter, make_context("interactsh"))
        candidates = payload_json(collector)["candidates"]
        assert candidates
        assert candidates[0]["provenance"]["oob"] is True


class TestSecretsAdapters:
    def test_trufflehog_redacts(self, golden_text):
        adapter = TrufflehogAdapter(runner=FakeRunner(stdout=golden_text("secrets/trufflehog.jsonl")))
        collector = collect(adapter, make_context("trufflehog", target="/repo"))
        records = payload_json(collector)["secrets"]["findings"]
        assert len(records) == 2
        assert "AKIAIOSFODNN7EXAMPLE" not in records[0]["masked_value"]
        assert records[0]["fingerprint"]
        assert records[0]["verified"] is True


class TestSastAdapters:
    def test_semgrep(self, golden_text):
        context = make_context("semgrep", target="/repo")
        adapter = SemgrepAdapter(runner=FakeRunner(stdout=golden_text("sast/semgrep.json")))
        collector = collect(adapter, context)
        candidates = payload_json(collector)["candidates"]
        assert candidates
        assert candidates[0]["check_id"].startswith("python.lang")
        assert candidates[0]["requires_validation"] is True


class TestProxyAdapters:
    def test_zap_alerts(self, golden_text):
        adapter = ZapAdapter(runner=FakeRunner(stdout=golden_text("proxy/zap.txt")))
        collector = collect(adapter, make_context("zap", target="https://example.com"))
        observations = payload_json(collector)["observations"]
        assert observations
        assert observations[0]["requires_validation"] is True

    def test_mitmproxy_requires_capture_file(self):
        adapter = MitmproxyAdapter(runner=FakeRunner())
        with pytest.raises(ValueError):
            adapter.build_argv(make_context("mitmproxy"))


class TestExploitAdapters:
    def test_searchsploit(self, golden_text):
        adapter = SearchsploitAdapter(runner=FakeRunner(stdout=golden_text("exploit/searchsploit.json")))
        collector = collect(adapter, make_context("searchsploit", target="wordpress sql injection"))
        references = payload_json(collector)["references"]
        assert references
        assert references[0]["kind"] == "exploit-reference"

    def test_exploitdb_inprocess(self, golden_text):
        import json

        database = json.loads(golden_text("exploit/exploitdb.json"))
        adapter = ExploitdbAdapter(runner=FakeRunner())
        context = make_context("exploitdb", params={"database": database, "query": "SQL Injection"})
        collector = collect(adapter, context)
        references = payload_json(collector)["references"]
        assert references[0]["title"].startswith("WordPress")

    def test_metasploit(self, golden_text):
        adapter = MetasploitAdapter(runner=FakeRunner(stdout=golden_text("exploit/metasploit.txt")))
        collector = collect(adapter, make_context("metasploit", target="example_sqli"))
        references = payload_json(collector)["references"]
        assert references and references[0]["source"] == "metasploit"
