# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution-dependent toolchain validation (Sprint 034.5).

These tests require the real external binaries and are EXCLUDED by default
(``pytest -m 'not tools'``). They exist to document and validate real-binary
execution; the adapter/parser/normalizer contract itself is fully certified by
the fixture-driven suites (tests/tools, tests/golden/tools) without binaries.
"""

from __future__ import annotations

import shutil

import pytest

from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

pytestmark = pytest.mark.tools


def _available(tool: str) -> bool:
    return shutil.which(tool) is not None


@pytest.mark.skipif(not _available("subfinder"), reason="subfinder binary not installed")
def test_subfinder_real_execution() -> None:
    """Execute the real subfinder binary against a benign public domain.

    Execution is bounded and classified; a clean run must complete and a
    forced timeout must classify as a timeout.
    """
    engine = ExecutionEngine()
    engine.register_adapter("subfinder", SubfinderAdapter())
    engine.install_hook("subfinder", lambda tool_id, version: "1.0.0")
    engine.install("subfinder", version="1.0.0")
    context = (
        ExecutionContextBuilder(tool_id="subfinder", target="example.com")
        .with_permissions(("network",))
        .with_timeout(30.0)
        .with_parameters({"mode": "passive"})
        .build()
    )
    result = engine.execute(context).result
    assert result.ok
    assert result.output.stdout


@pytest.mark.skipif(not _available("subfinder"), reason="subfinder binary not installed")
def test_subfinder_real_timeout_classified() -> None:
    engine = ExecutionEngine()
    engine.register_adapter("subfinder", SubfinderAdapter())
    engine.install_hook("subfinder", lambda tool_id, version: "1.0.0")
    engine.install("subfinder", version="1.0.0")
    context = (
        ExecutionContextBuilder(tool_id="subfinder", target="example.com")
        .with_permissions(("network",))
        .with_timeout(0.05)
        .with_parameters({"mode": "passive"})
        .build()
    )
    result = engine.execute(context).result
    assert not result.ok
    assert result.status.value in ("failed", "timed-out")
