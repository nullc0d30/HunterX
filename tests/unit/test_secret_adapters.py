# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the secret discovery tool adapters.

The gitleaks adapter is exercised with a fake binary runner fed golden JSON
output so no external tool or network is required. Tests assert the generated
command line, the redacted canonical secret records, and the invariant that raw
secret values never escape the adapter into findings or assets.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.secrets.gitleaks import GitleaksAdapter
from hunterx.tools.secrets.registry import (
    SECRETS_TOOL_IDS,
    SecretsAdapterFactory,
    register_secrets_adapters,
    secrets_adapters,
)
from hunterx.tools.secrets.tip import register_secrets_tools, secrets_tool_ids

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "secrets"


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`."""

    def __init__(self, result: CommandResult | None = None, *, stdout: str = "") -> None:
        super().__init__()
        self._result = result or CommandResult(returncode=0, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        self.calls.append(tuple(argv))
        return self._result


def _context(tool_id: str, *, target: str = "/workspace/repo", params: dict[str, object] | None = None) -> ExecutionContext:
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("filesystem",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


def _collect(adapter: GitleaksAdapter, context: ExecutionContext) -> OutputCollector:
    collector = OutputCollector()
    adapter.run(context, collector)
    return collector


def _payload(collector: OutputCollector) -> dict[str, object]:
    return collector.build().json or {}


def _findings(collector: OutputCollector) -> list[dict[str, object]]:
    payload = _payload(collector)
    findings = payload["secrets"]
    assert isinstance(findings, dict)
    records = findings["findings"]
    assert isinstance(records, list)
    return records


def _golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8")


class TestGitleaksAdapter:
    def test_default_argv(self) -> None:
        adapter = GitleaksAdapter()
        argv = adapter.build_argv(_context("gitleaks"))
        assert argv[:6] == ["gitleaks", "detect", "--source", "/workspace/repo", "--report-format", "json"]
        assert "--redact" in argv
        assert argv[argv.index("--report-path") + 1] == "-"

    def test_report_path_param(self) -> None:
        adapter = GitleaksAdapter()
        argv = adapter.build_argv(_context("gitleaks", params={"report_path": "artifacts/gitleaks.json"}))
        assert argv[argv.index("--report-path") + 1] == "artifacts/gitleaks.json"

    def test_parses_golden_output(self) -> None:
        adapter = GitleaksAdapter(runner=FakeRunner(stdout=_golden("gitleaks.json")))
        collector = _collect(adapter, _context("gitleaks"))
        findings = _findings(collector)
        assert len(findings) == 3
        types = {str(finding["secret_type"]) for finding in findings}
        assert types == {"generic-api-key", "github-pat", "aws-access-token"}

    def test_raw_secrets_never_escape(self) -> None:
        adapter = GitleaksAdapter(runner=FakeRunner(stdout=_golden("gitleaks.json")))
        collector = _collect(adapter, _context("gitleaks"))
        findings = _findings(collector)
        for finding in findings:
            assert "secret" not in finding
            assert "match" not in finding
            assert finding["masked_value"] != "AKIAIOSFODNN7EXAMPLE"
            assert finding["masked_value"] != "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
            assert "…" in finding["masked_value"] or "***" in finding["masked_value"] or finding["masked_value"].endswith("***")

    def test_redacted_fields_only(self) -> None:
        adapter = GitleaksAdapter(runner=FakeRunner(stdout=_golden("gitleaks.json")))
        collector = _collect(adapter, _context("gitleaks"))
        findings = _findings(collector)
        allowed = {
            "secret_type", "location", "fingerprint", "masked_value", "entropy",
            "confidence", "source", "line", "commit", "author", "date", "tags",
            "tool_id", "tool_version", "correlation_id", "mission_id",
            "execution_id", "provenance",
        }
        for finding in findings:
            assert set(finding) <= allowed

    def test_fingerprint_is_deterministic(self) -> None:
        adapter = GitleaksAdapter(runner=FakeRunner(stdout=_golden("gitleaks.json")))
        collector = _collect(adapter, _context("gitleaks"))
        findings = _findings(collector)
        assert len({finding["fingerprint"] for finding in findings}) == 3

    def test_src_prefix_stripped(self) -> None:
        adapter = GitleaksAdapter(runner=FakeRunner(stdout=_golden("gitleaks.json")))
        collector = _collect(adapter, _context("gitleaks"))
        locations = {str(finding["location"]) for finding in _findings(collector)}
        assert "config.py" in locations
        assert "hunterx/cloud/aws.py" in locations


class TestRegistry:
    def test_secrets_tool_ids(self) -> None:
        assert SECRETS_TOOL_IDS == secrets_tool_ids() == ("gitleaks", "trufflehog")

    def test_factory_builds_all(self) -> None:
        adapters = SecretsAdapterFactory().build()
        assert set(adapters) == set(SECRETS_TOOL_IDS)

    def test_register_on_engine(self) -> None:
        engine = ExecutionEngine()
        mapping = register_secrets_adapters(engine)
        for tool_id in SECRETS_TOOL_IDS:
            assert engine.adapter_for(tool_id) is mapping[tool_id]

    def test_adapters_helper(self) -> None:
        assert set(secrets_adapters()) == set(SECRETS_TOOL_IDS)


class TestTip:
    def test_register_secrets_tools(self) -> None:
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI

        tip = ToolIntelligenceAPI()
        register_secrets_tools(tip)
        assert tip.get_tool("gitleaks") is not None
        knowledge = tip.get_knowledge("gitleaks")
        assert "secrets-scan" in knowledge.capabilities
        schema_fields = {field.name for field in knowledge.output_schema.fields}
        assert "secret" not in schema_fields and "match" not in schema_fields
        assert "fingerprint" in schema_fields and "masked_value" in schema_fields


class TestPipeline:
    def test_adapter_end_to_end_through_sdk(self) -> None:
        engine = ExecutionEngine()
        adapters = register_secrets_adapters(engine)
        adapters["gitleaks"]._runner = FakeRunner(stdout=_golden("gitleaks.json"))
        engine.install_hook("gitleaks", lambda _tid, _version: "1.0.0")
        engine.install("gitleaks", version="1.0.0")
        context = _context("gitleaks")
        outcome = engine.execute(context)
        assert outcome.result.status.is_success
        payload = outcome.result.output.json
        assert payload is not None
        assert len(payload["secrets"]["findings"]) == 3
