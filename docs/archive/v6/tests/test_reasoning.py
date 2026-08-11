# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.reasoning_engine_old import ReasoningEngine
from core.context import TargetContext

def test_lfi_chain_linux():
    engine = ReasoningEngine()
    findings = [{"payload_category": "LFI", "diff_score": 85, "findings": ["LFI detected"]}]
    ctx = TargetContext()
    ctx.os = {"linux": 0.99, "windows": 0.01}
    chains = engine.reason(findings, ctx)
    assert any("LFI -> Log Poisoning" in c["chain"] for c in chains)
    assert any("LFI -> /proc/self/environ" in c["chain"] for c in chains)

def test_lfi_chain_windows():
    engine = ReasoningEngine()
    findings = [{"payload_category": "LFI", "diff_score": 85, "findings": ["LFI detected"]}]
    ctx = TargetContext()
    ctx.os = {"windows": 0.99, "linux": 0.01}
    chains = engine.reason(findings, ctx)
    assert any("SAM Hive Extraction" in c["chain"] for c in chains)

def test_ssti_chain():
    engine = ReasoningEngine()
    findings = [{"payload_category": "SSTI", "diff_score": 90, "findings": ["SSTI detected"]}]
    chains = engine.reason(findings, TargetContext())
    assert any("SSTI -> RCE" in c["chain"] for c in chains)

def test_no_findings():
    engine = ReasoningEngine()
    chains = engine.reason([], TargetContext())
    assert len(chains) == 0
