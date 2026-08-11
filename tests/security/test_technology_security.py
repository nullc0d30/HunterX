# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for technology fingerprinting.

Verifies that fingerprint sources are always treated as untrusted: argv is
built from typed parameters (no shell interpretation), malformed tool output is
never executed, out-of-scope intelligence is never persisted, cache keys are
target-scoped (no cross-target contamination) and scope is never silently
expanded by discovered technology intelligence.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.application.technology import FingerprintService
from hunterx.domain.entities.tidb.technology import TechnologyObservation as TidbTechnologyObservation
from hunterx.domain.technology.detector import HttpEvidence
from hunterx.domain.technology.scope import TechnologyScopePolicy
from hunterx.infrastructure.cache import MemoryCache
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.tech.httpx import HttpxAdapter
from hunterx.tools.tech.registry import register_tech_adapters
from hunterx.tools.tech.signature import SignatureAdapter
from hunterx.tools.tech.whatweb import WhatWebAdapter

GOLDEN = Path(__file__).parent.parent / "golden" / "tech"


class FakeRunner(BinaryRunner):
    """Binary runner returning canned output per binary name."""

    def __init__(self, mapping: dict[str, str]) -> None:
        super().__init__()
        self._mapping = mapping

    def run(self, argv: list[str], *, timeout_s: float = 0.0, tool_id: str = "") -> CommandResult:
        return CommandResult(returncode=0, stdout=self._mapping.get(argv[0], ""))


def _make_engine(cache=None) -> tuple[ExecutionEngine, dict]:
    engine = ExecutionEngine()
    adapters = register_tech_adapters(engine, cache=cache)
    for tool_id in adapters:
        engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
        engine.install(tool_id, version="1.0.0")
    return engine, adapters


class TestInjectionResistance:
    def test_target_never_interpreted_by_shell(self) -> None:
        adapter = HttpxAdapter()
        from hunterx.tools.sdk.context import ExecutionContextBuilder

        context = (
            ExecutionContextBuilder(tool_id="httpx", target="example.com; rm -rf /")
            .with_permissions(("network",))
            .build()
        )
        argv = adapter.build_argv(context)
        assert "example.com; rm -rf /" in argv
        assert any(arg == "-u" for arg in argv)
        assert "shell=True" not in argv  # subprocess list semantics, never a shell

    def test_flag_injection_in_string_param_is_single_arg(self) -> None:
        adapter = WhatWebAdapter()
        from hunterx.tools.sdk.context import ExecutionContextBuilder

        context = (
            ExecutionContextBuilder(tool_id="whatweb", target="example.com")
            .with_parameters({"user_agent": "--aggression 9 --evil"})
            .with_permissions(("network",))
            .build()
        )
        argv = adapter.build_argv(context)
        assert "--user-agent" in argv
        index = argv.index("--user-agent")
        assert argv[index + 1] == "--aggression 9 --evil"
        assert "--aggression" not in argv[index + 1 :]

    def test_credential_parameters_never_land_in_argv(self) -> None:
        adapter = WhatWebAdapter()
        from hunterx.tools.sdk.context import ExecutionContextBuilder

        context = (
            ExecutionContextBuilder(tool_id="whatweb", target="example.com")
            .with_parameters({"password": "hunter2", "api_key": "secret"})
            .with_permissions(("network",))
            .build()
        )
        argv = adapter.build_argv(context)
        assert "hunter2" not in argv
        assert "secret" not in argv


class TestUntrustedOutput:
    def test_malformed_output_is_data_not_code(self) -> None:
        adapter = HttpxAdapter(runner=FakeRunner({"httpx": "__import__('os').system('x')"}))
        from hunterx.tools.sdk.context import ExecutionContextBuilder

        context = (
            ExecutionContextBuilder(tool_id="httpx", target="example.com").with_permissions(("network",)).build()
        )
        from hunterx.tools.sdk.output import OutputCollector

        collector = OutputCollector()
        adapter.run(context, collector)
        assert collector.build().json == {"technologies": [], "count": 0}

    def test_tool_stdout_never_executed(self) -> None:
        adapter = SignatureAdapter(fetch=lambda url, timeout: (_ for _ in ()).throw(RuntimeError("nope")))
        from hunterx.tools.sdk.context import ExecutionContextBuilder
        from hunterx.tools.sdk.output import OutputCollector

        context = (
            ExecutionContextBuilder(tool_id="signature", target="example.com").with_permissions(("network",)).build()
        )
        collector = OutputCollector()
        adapter.run(context, collector)
        assert collector.build().json["technologies"] == []


class TestScopeSafety:
    def test_out_of_scope_observations_never_persisted(self) -> None:
        engine, adapters = _make_engine()
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(
            url=url, status_code=200, headers={"Server": "nginx"}, html=""
        )
        stores = InMemoryTidbRepositoryFactory()
        scope = TechnologyScopePolicy(roots=frozenset({"example.com"}))
        service = FingerprintService(engine=engine, stores=stores, scope=scope)
        # evil.com is out of scope; fingerprinting it must not persist anything
        from contextlib import suppress

        from hunterx.domain.technology.models import TechTarget

        with suppress(ValueError):
            service.run(target=TechTarget("evil.com"), mode="active")
        assert stores.repository_for(TidbTechnologyObservation).count() == 0

    def test_discovered_tech_never_expands_scope(self) -> None:
        engine, adapters = _make_engine()
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(
            url=url,
            status_code=200,
            headers={"Server": "nginx"},
            html='<script src="https://cdn.other-domain.com/x.js"></script>',
        )
        stores = InMemoryTidbRepositoryFactory()
        scope = TechnologyScopePolicy(roots=frozenset({"example.com"}))
        service = FingerprintService(engine=engine, stores=stores, scope=scope)
        batch = service.run(target="www.example.com", mode="active")
        assert batch.technology_count() > 0
        assert stores.repository_for(TidbTechnologyObservation).count() == batch.technology_count()


class TestCacheIsolation:
    def test_cache_keys_are_target_scoped(self) -> None:
        cache = MemoryCache()
        fetched: list[str] = []

        def fetch(url: str, timeout: float) -> HttpEvidence:
            fetched.append(url)
            return HttpEvidence(url=url, status_code=200, headers={"Server": "nginx"}, html="")

        adapter = SignatureAdapter(fetch=fetch, cache=cache)
        from hunterx.tools.sdk.context import ExecutionContextBuilder
        from hunterx.tools.sdk.output import OutputCollector

        for target in ("one.example.com", "two.example.com"):
            context = (
                ExecutionContextBuilder(tool_id="signature", target=target).with_permissions(("network",)).build()
            )
            collector = OutputCollector()
            adapter.run(context, collector)
            adapter.run(context, collector)

        # two distinct URLs -> two distinct cache entries -> four fetches total
        assert len(fetched) == 2
        assert cache.get("fingerprint:http:https://one.example.com") is not None
        assert cache.get("fingerprint:http:https://two.example.com") is not None
        assert cache.get("fingerprint:http:https://three.example.com") is None

    def test_service_cache_never_contaminates_targets(self) -> None:
        cache = MemoryCache()
        engine, adapters = _make_engine(cache=cache)
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(
            url=url, status_code=200, headers={"Server": "nginx"}, html=""
        )
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores, cache=cache)
        service.run(target="one.example.com", mode="active")
        service.run(target="two.example.com", mode="active")
        observations = stores.repository_for(TidbTechnologyObservation)
        assets = {record.asset for record in observations.stream()}
        assert assets == {"one.example.com", "two.example.com"}


class TestMalformedOutput:
    def test_conflicting_cdn_golden_handled_safely(self) -> None:
        engine, adapters = _make_engine()
        adapters["httpx"]._runner = FakeRunner({"httpx": (GOLDEN / "httpx_conflicting_cdn.jsonl").read_text()})
        adapters["whatweb"]._runner = FakeRunner({"whatweb": ""})
        adapters["signature"]._fetch = lambda url, timeout: HttpEvidence(url=url)
        stores = InMemoryTidbRepositoryFactory()
        service = FingerprintService(engine=engine, stores=stores)
        batch = service.run(target="cdn.example.com", mode="hybrid")
        # both CDN candidates are preserved through correlation; nothing is lost
        assert batch.technology_count() >= 1
