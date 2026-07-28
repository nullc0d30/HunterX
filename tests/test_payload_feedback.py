import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.payload_feedback import PayloadFeedbackLoop


def test_feedback_init():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        summary = feedback.get_summary()
        assert summary["total"] == 0


def test_feedback_record_success():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        record = feedback.record_result(
            payload="test_payload",
            category="XSS",
            success=True,
            status_code=200,
        )
        assert record.success is True
        assert record.category == "XSS"
        summary = feedback.get_summary()
        assert summary["total"] == 1
        assert summary["success_rate"] == 1.0


def test_feedback_record_blocked():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        feedback.record_result(
            payload="<script>alert(1)</script>",
            category="XSS",
            success=False,
            blocked=True,
            waf_blocked=True,
        )
        summary = feedback.get_summary()
        assert summary["block_rate"] == 1.0


def test_feedback_success_rate():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        feedback.record_result(payload="p1", category="SQLI", success=True)
        feedback.record_result(payload="p2", category="SQLI", success=False)
        feedback.record_result(payload="p3", category="SQLI", success=True)
        rate = feedback.get_success_rate(category="SQLI")
        assert rate == 2.0 / 3.0


def test_feedback_block_rate():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        feedback.record_result(payload="p1", category="RCE", success=True)
        feedback.record_result(payload="p2", category="RCE", success=False, blocked=True)
        rate = feedback.get_block_rate(category="RCE")
        assert rate == 0.5


def test_feedback_top_performing():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        for i in range(5):
            feedback.record_result(
                payload=f"payload_{i}",
                category="SQLI",
                success=(i % 2 == 0),
            )
        top = feedback.get_top_performing(top_n=3, min_attempts=1)
        assert len(top) > 0
        for t in top:
            assert t["attempts"] >= 1


def test_feedback_get_recent():
    with tempfile.TemporaryDirectory() as tmp:
        feedback = PayloadFeedbackLoop(storage_path=tmp)
        for i in range(10):
            feedback.record_result(payload=f"p{i}", category="XSS", success=True)
        recent = feedback.get_recent_feedback(limit=5)
        assert len(recent) == 5
