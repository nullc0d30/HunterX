# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Engine-level tool execution integration tests.

Adapters run through the real :class:`ExecutionEngine` pipeline with a fake
runner, so execution classification, output formats, artifacts and retries are
certified end-to-end without any binary.
"""

from __future__ import annotations

from hunterx.domain.execution import ExecutionStatus, OutputFormat
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.tools.conftest import FakeRunner, make_context


def _engine(stdout: str) -> ExecutionEngine:
    engine = ExecutionEngine()
    engine.register_adapter("subfinder", SubfinderAdapter(runner=FakeRunner(stdout=stdout)))
    engine.install_hook("subfinder", lambda tool_id, version: "1.0.0")
    engine.install("subfinder", version="1.0.0")
    return engine


class TestPipelineExecution:
    def test_successful_execution_completes(self):
        result = _engine('{"host": "api.example.com", "source": "crt.sh"}\n').execute(
            make_context("subfinder")
        ).result
        assert result.ok
        assert result.status is ExecutionStatus.COMPLETED
        assert result.output.stdout
        assert OutputFormat.JSON in result.output.formats
        assert result.retry_count == 0

    def test_empty_result_is_completed_not_failure(self):
        result = _engine("").execute(make_context("subfinder")).result
        assert result.ok
        assert result.status is ExecutionStatus.COMPLETED

    def test_execution_records_normalization_flag(self):
        result = _engine('{"host": "a.example.com"}\n').execute(make_context("subfinder")).result
        assert result.normalized is True
        assert result.started_at
        assert result.completed_at

    def test_unsupported_tool_fails_closed(self):
        import pytest

        engine = _engine('{"host": "a.example.com"}\n')
        # No adapter registered → the engine refuses to execute (fail-closed).
        with pytest.raises(LookupError):
            engine.execute(make_context("nmap"))

    def test_health_gate_blocks_uninstalled_tool(self):
        engine = ExecutionEngine()
        engine.register_adapter("subfinder", SubfinderAdapter(runner=FakeRunner()))
        result = engine.execute(make_context("subfinder")).result
        assert not result.ok
        assert result.status in (ExecutionStatus.FAILED, ExecutionStatus.RETRYING)


class TestOfflineReplay:
    def test_parse_round_trip(self):
        from hunterx.platform import build_platform

        service = build_platform().toolchain_service
        parsed = service.parse("subfinder", '{"host": "api.example.com", "source": "crt.sh"}')
        assert parsed["count"] == 1

    def test_contract_gaps_are_empty(self):
        from hunterx.platform import build_platform

        gaps = build_platform().toolchain_service.contract_gaps()
        assert not gaps, gaps
