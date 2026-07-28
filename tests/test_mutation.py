# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.mutation_engine import MutationEngine

def test_mutation_original():
    me = MutationEngine("high")
    variants = me.mutate("../../etc/passwd", "LFI")
    assert any(v["technique"] == "original" for v in variants)

def test_mutation_url_encoding():
    me = MutationEngine("high")
    variants = me.mutate("<script>alert(1)</script>", "XSS")
    techniques = {v["technique"] for v in variants}
    assert "url_encode" in techniques

def test_mutation_sql():
    me = MutationEngine("high")
    variants = me.mutate("' OR 1=1 --", "SQLI")
    techniques = {v["technique"] for v in variants}
    assert "sql_comment_ws" in techniques

def test_mutation_lfi():
    me = MutationEngine("high")
    variants = me.mutate("../../../etc/passwd", "LFI")
    techniques = {v["technique"] for v in variants}
    assert "lfi_double_dot" in techniques

def test_low_evasion():
    me = MutationEngine("low")
    variants = me.mutate("test", "GENERIC")
    assert len(variants) == 1
