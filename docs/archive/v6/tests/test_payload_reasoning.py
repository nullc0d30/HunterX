import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.payload_reasoning import PayloadReasoning, ReasoningExplanation
from core.payload_index import IndexedPayload


def test_reasoning_explanation_defaults():
    exp = ReasoningExplanation(reason="test reason")
    assert exp.reason == "test reason"
    assert exp.confidence == 1.0
    assert exp.contributing_factors == []


def test_reasoning_explanation_to_dict():
    exp = ReasoningExplanation(
        reason="test",
        confidence=0.8,
        contributing_factors=["factor1"],
        warnings=["warning1"],
    )
    d = exp.to_dict()
    assert d["reason"] == "test"
    assert d["confidence"] == 0.8


def test_reasoning_reason_no_candidates():
    reasoner = PayloadReasoning()
    results = reasoner.reason({"target": "http://test.com"}, category="NONEXISTENT", top_n=5)
    assert results == []


def test_reasoning_explain_no_context():
    payload = IndexedPayload(
        row_id=1,
        filename="test.txt",
        file_path="RCE/test.txt",
        category="RCE",
        payload_text="cat /etc/passwd",
        payload_hash="abc123",
        technology=["PHP"],
        framework=[],
        language=[],
    )
    reasoner = PayloadReasoning()
    exp = reasoner.explain(payload, {"target": "http://test.com"})
    assert exp.reason is not None
    assert "RCE" in exp.reason or "rce" in exp.reason.lower()


def test_reasoning_batch_empty():
    reasoner = PayloadReasoning()
    results = reasoner.reason_batch([], {"target": "http://test.com"})
    assert results == []


def test_reasoning_is_noisy():
    payload = IndexedPayload(
        row_id=1,
        filename="test.txt",
        file_path="test.txt",
        category="RCE",
        payload_text="sleep(5)",
        payload_hash="def456",
    )
    reasoner = PayloadReasoning()
    assert reasoner._is_noisy(payload) is True


def test_reasoning_estimate_danger():
    reasoner = PayloadReasoning()
    assert reasoner._estimate_danger("cat /etc/passwd", "RCE") > 0.8
    assert reasoner._estimate_danger("hello", "XSS") < 0.7
