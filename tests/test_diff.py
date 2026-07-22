# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# All Rights Reserved.
#
# HunterX — AI-Assisted Vulnerability Hunter
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.diff import ResponseDiffer
from core.fingerprint import Fingerprint

class FakeResponse:
    def __init__(self, status_code=200, content=b"", text=""):
        self.status_code = status_code
        self.content = content
        self.text = text

def test_diff_identical():
    differ = ResponseDiffer()
    baseline = Fingerprint(
        url="http://test.com",
        status_code=200,
        content_length=100,
        headers={},
        body_hash="abc",
        response_time=0.5,
        text="Hello World" * 10,
    )
    resp = FakeResponse(200, b"Hello World" * 10, "Hello World" * 10)
    result = differ.diff(baseline, resp)
    assert result["score"] == 0

def test_diff_status_change():
    differ = ResponseDiffer()
    baseline = Fingerprint(
        url="http://test.com",
        status_code=200,
        content_length=100,
        headers={},
        body_hash="abc",
        response_time=0.5,
        text="Hello World" * 10,
    )
    resp = FakeResponse(500, b"Error" * 10, "Error" * 10)
    result = differ.diff(baseline, resp)
    assert result["score"] > 0
    assert any("Status changed" in r for r in result["reasons"])

def test_diff_no_response():
    differ = ResponseDiffer()
    baseline = Fingerprint(
        url="http://test.com",
        status_code=200,
        content_length=100,
        headers={},
        body_hash="abc",
        response_time=0.5,
        text="Hello World" * 10,
    )
    result = differ.diff(baseline, None)
    assert result["score"] == 0

def test_diff_score_range():
    differ = ResponseDiffer()
    baseline = Fingerprint(
        url="http://test.com",
        status_code=200,
        content_length=50,
        headers={},
        body_hash="abc",
        response_time=0.5,
        text="Baseline content here",
    )
    resp = FakeResponse(403, b"Forbidden" * 20, "Forbidden" * 20)
    result = differ.diff(baseline, resp)
    assert 0 <= result["score"] <= 100
