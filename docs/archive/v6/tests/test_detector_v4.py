# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.detector import Detector

def test_expanded_lfi_signatures():
    d = Detector()
    assert any("LFI" in r for r in d.scan("root:x:0:0:"))
    assert any("LFI" in r for r in d.scan("DB_HOST=localhost;DB_USER=root"))
    assert any("LFI" in r for r in d.scan("-----BEGIN RSA PRIVATE KEY-----"))
    assert any("LFI" in r for r in d.scan("aws_access_key_id=AKIA"))

def test_expanded_rce_signatures():
    d = Detector()
    assert any("RCE" in r for r in d.scan("uid=0(root) gid=0(root)"))
    assert any("RCE" in r for r in d.scan("Linux ubuntu 5.4.0-26-generic"))
    assert any("RCE" in r for r in d.scan("total 24\ndrwxr-xr-x 2 root root 4096"))

def test_expanded_sqli_signatures():
    d = Detector()
    assert any("SQLi" in r for r in d.scan("Unclosed quotation mark"))
    assert any("SQLi" in r for r in d.scan("Incorrect syntax near 'SELECT'"))
    assert any("SQLi" in r for r in d.scan('Table "users" doesn\'t exist'))

def test_expanded_ssti_signatures():
    d = Detector()
    assert any("SSTI" in r for r in d.scan("__class__.__mro__"))
    assert any("SSTI" in r for r in d.scan("os.popen('id')"))

def test_ssrf_signatures():
    d = Detector()
    assert any("SSRF" in r for r in d.scan("169.254.169.254"))
    assert any("SSRF" in r for r in d.scan("iam/security-credentials"))

def test_info_disclosure():
    d = Detector()
    assert any("Info Disclosure" in r for r in d.scan("Traceback (most recent call last)"))
    assert any("Info Disclosure" in r for r in d.scan("SECRET_KEY = 'mysecret'"))

def test_scan_headers():
    d = Detector()
    findings = d.scan_headers({"Server": "Apache/2.4.51", "X-Powered-By": "PHP/8.1"})
    assert len(findings) == 2
