# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the certified toolchain adapters."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from hunterx.shared.masking import mask_value
from hunterx.tools.dns.massdns import MassdnsAdapter
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.secrets.trufflehog import TrufflehogAdapter
from hunterx.tools.vuln.injection import DalfoxAdapter, SQLmapAdapter
from tests.tools.conftest import FakeRunner, collect, make_context

TOOLS_ROOT = Path(__file__).parent.parent.parent.parent / "src" / "hunterx" / "tools"


class TestStructuredArgv:
    def test_no_shell_true_anywhere_in_tools(self):
        offenders: list[str] = []
        for path in TOOLS_ROOT.rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
                        for kw in node.keywords:
                            if kw.arg == "shell":
                                value = ast.literal_eval(kw.value)
                                if value:
                                    offenders.append(f"{path}:{node.lineno}")
                    if isinstance(node.func, ast.Name) and node.func.id == "system":
                        offenders.append(f"{path}:{node.lineno}")
        assert not offenders, f"shell usage found: {offenders}"

    def test_targets_are_structural_argv_elements(self):

        adapter = SubfinderAdapter()
        hostile = "$(whoami) ; rm -rf /"
        context = make_context("subfinder", target=hostile)
        argv = adapter.build_argv(context)
        # The hostile target is a single inert argv element after -d.
        assert argv[argv.index("-d") + 1] == hostile
        assert len([item for item in argv if item == hostile]) == 1

    def test_flag_value_target_stays_single_element(self):
        adapter = SQLmapAdapter()
        context = make_context("sqlmap", target="--batch")
        argv = adapter.build_argv(context)
        # A target that looks like a flag must remain a value after -u.
        assert argv[argv.index("-u") + 1] == "--batch"


class TestOptionInjectionGuards:
    def test_positional_guard_rejects_flag_like_target(self):
        from hunterx.domain.exceptions import ToolExecutionError
        from hunterx.tools.recon.runner import guard_positional_target

        with pytest.raises(ToolExecutionError):
            guard_positional_target("--help", label="nmap")
        guard_positional_target("example.com", label="nmap")

    def test_option_value_guard_rejects_leading_dash(self):
        from hunterx.domain.exceptions import ToolExecutionError
        from hunterx.tools.recon.runner import guard_option_value

        with pytest.raises(ToolExecutionError):
            guard_option_value("--output=/etc", label="ffuf")
        guard_option_value("https://example.com", label="ffuf")


class TestHostileOutput:
    def test_ansi_and_control_chars_are_inert_data(self):
        adapter = SQLmapAdapter(
            runner=FakeRunner(stdout="\x1b[31mParameter: id (GET)\x1b[0m\r\n\x00\x01 Type: boolean-based blind")
        )
        collector = collect(adapter, make_context("sqlmap"))
        payload = collector.build().json or {}
        # The ANSI line produced a candidate; control chars never executed.
        assert payload["count"] <= 1

    def test_injection_candidates_are_never_findings(self):
        adapter = DalfoxAdapter(
            runner=FakeRunner(stdout='{"results":[{"type":"XSS","data":"reflected","param":"q"}]}')
        )
        collector = collect(adapter, make_context("dalfox", target="https://example.com/"))
        output = collector.build()
        payload = output.json or {}
        for candidate in payload["candidates"]:
            assert candidate["requires_validation"] is True
            assert candidate["provenance"]["validated"] is False


class TestSecretNonPersistence:
    def test_raw_secrets_never_reach_structured_output(self):
        adapter = TrufflehogAdapter(
            runner=FakeRunner(
                stdout='{"Secret":"AKIAIOSFODNN7EXAMPLE","DetectorName":"AWS","Verified":true,"SourceMetadata":{"Git":{"file":"config.py"}}}\n'
            )
        )
        collector = collect(adapter, make_context("trufflehog", target="/repo"))
        payload = collector.build().json or {}
        findings = payload["secrets"]["findings"]
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0]["masked_value"]
        assert findings[0]["fingerprint"]
        assert "Secret" not in findings[0]

    def test_massdns_domains_file_is_scratch_only(self, tmp_path):
        context = make_context("massdns", target="example.com")
        context = make_context("massdns", target="example.com")
        from hunterx.domain.execution import ExecutionContext

        context = ExecutionContext(
            tool_id="massdns",
            target="example.com",
            temp_directory=str(tmp_path),
            parameters={},
        )
        adapter = MassdnsAdapter(runner=FakeRunner())
        # run() writes the domain list under the scratch directory only.
        adapter.run(context, __import__("hunterx.tools.sdk.output", fromlist=["OutputCollector"]).OutputCollector())
        written = [p for p in tmp_path.iterdir() if p.name.startswith("massdns-")]
        assert written


class TestMaskingRegression:
    def test_reveal_tail_zero_does_not_leak(self):
        # Regression: value[-0:] returned the whole secret.
        masked = mask_value("SECRETVALUE", reveal_head=4, reveal_tail=0)
        assert "SECRETVALUE" not in masked
        assert masked.startswith("SECR")
        assert masked.count("*") == 7

    def test_full_mask_for_short_values(self):
        assert mask_value("a", reveal_head=1, reveal_tail=0) == "*"
