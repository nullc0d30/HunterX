import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.payload_policy import PayloadExecutionPolicy, PolicyLevel
from core.payload_metadata import PayloadMetadata, PayloadMetadataEngine


def test_policy_default_level():
    policy = PayloadExecutionPolicy()
    assert policy.config.level == PolicyLevel.BALANCED


def test_policy_set_level():
    policy = PayloadExecutionPolicy()
    policy.set_level(PolicyLevel.SAFE)
    assert policy.config.level == PolicyLevel.SAFE
    assert policy.config.allow_dangerous is False
    assert policy.config.max_payloads_per_category == 5


def test_policy_aggressive():
    policy = PayloadExecutionPolicy(PolicyLevel.AGGRESSIVE)
    assert policy.config.allow_dangerous is True
    assert policy.config.max_payloads_per_category == 25


def test_policy_evaluate_safe():
    policy = PayloadExecutionPolicy(PolicyLevel.SAFE)
    meta = PayloadMetadata(category="XSS", danger_level=0.2, noise_level=0.2, reliability=0.8)
    ok, reason = policy.evaluate("<script>alert(1)</script>", meta, category="XSS")
    assert ok is True, f"Expected allowed but got: {reason}"


def test_policy_evaluate_blocked():
    policy = PayloadExecutionPolicy(PolicyLevel.SAFE)
    policy.config.blocked_categories = ["SQLI"]
    meta = PayloadMetadata(category="SQLI")
    ok, reason = policy.evaluate("' OR 1=1 --", meta, category="SQLI")
    assert ok is False
    assert "blocked" in reason.lower()


def test_policy_evaluate_dangerous():
    policy = PayloadExecutionPolicy(PolicyLevel.SAFE)
    meta = PayloadMetadata(category="RCE", danger_level=0.95, noise_level=0.1)
    ok, reason = policy.evaluate("cat /etc/passwd", meta, category="RCE")
    assert ok is False
    assert "danger" in reason.lower()


def test_policy_filter_payloads():
    policy = PayloadExecutionPolicy(PolicyLevel.BALANCED)
    payloads = [
        {"payload": "safe test", "category": "XSS"},
        {"payload": "rm -rf /", "category": "RCE"},
    ]
    meta_map = {}
    for p in payloads:
        meta = PayloadMetadataEngine().analyze(p["payload"], p["payload"], category=p["category"])
        meta_map[p.get("payload_hash", p["payload"][:32])] = meta
    filtered = policy.filter_payloads(payloads, metadata_map=meta_map)
    assert len(filtered) == 1
    assert filtered[0]["category"] == "XSS"


def test_policy_research():
    policy = PayloadExecutionPolicy(PolicyLevel.RESEARCH)
    assert policy.config.allow_dangerous is True
    assert policy.config.max_payloads_per_category == 100
    assert policy.config.max_concurrent_payloads == 50
