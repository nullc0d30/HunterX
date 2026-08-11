# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.detector import Detector

def test_lfi_detection():
    d = Detector()
    results = d.scan("root:x:0:0:root:/root:/bin/bash")
    assert any("LFI" in r for r in results)

def test_rce_detection():
    d = Detector()
    results = d.scan("uid=0(root) gid=0(root)")
    assert any("RCE" in r for r in results)

def test_sqli_detection():
    d = Detector()
    results = d.scan("SQL syntax error near '1'")
    assert any("SQLi" in r for r in results)

def test_no_false_positives():
    d = Detector()
    results = d.scan("Normal HTML content with no vulnerability indicators")
    assert len(results) == 0

def test_heuristics_reflection():
    d = Detector()
    results = d.check_heuristics("baseline text", "response with <test>payload</test>", "<test>payload</test>")
    assert any("Reflected" in r for r in results)

def test_heuristics_no_false_positive():
    d = Detector()
    results = d.check_heuristics("baseline text with <test>payload</test>", "response with <test>payload</test>", "<test>payload</test>")
    assert len(results) == 0
