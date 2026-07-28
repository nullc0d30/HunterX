# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Payload Evolution Engine
import json
from core.evolution import (
    PayloadEvolutionEngine,
    PayloadScore,
    mutate_case,
    mutate_encoding,
    mutate_whitespace,
    mutate_comment_injection,
    mutate_null_byte,
    mutate_unicode,
)


class TestPayloadScore:
    def test_create(self):
        ps = PayloadScore(
            payload_hash="abc123",
            payload="<script>alert(1)</script>",
            category="XSS",
        )
        assert ps.payload_hash == "abc123"
        assert ps.attempts == 0

    def test_update_success(self):
        ps = PayloadScore(payload_hash="abc", payload="test", category="LFI")
        ps.update(success=True)
        assert ps.attempts == 1
        assert ps.successes == 1
        assert ps.success_rate == 1.0

    def test_update_blocked(self):
        ps = PayloadScore(payload_hash="abc", payload="test", category="LFI")
        ps.update(success=False, blocked=True)
        assert ps.waf_reaction > 0

    def test_to_dict(self):
        ps = PayloadScore(payload_hash="abc", payload="test", category="XSS")
        ps.update(success=True)
        d = ps.to_dict()
        assert d["category"] == "XSS"
        assert d["attempts"] == 1


class TestMutationFunctions:
    def test_mutate_case(self):
        result = mutate_case("HelloWorld")
        assert len(result) > 0

    def test_mutate_encoding(self):
        result = mutate_encoding("<script>")
        assert any("%3C" in v for v in result)

    def test_mutate_whitespace(self):
        result = mutate_whitespace("SELECT * FROM users")
        assert len(result) > 0

    def test_mutate_comment_injection(self):
        result = mutate_comment_injection("union select")
        assert len(result) > 0

    def test_mutate_null_byte(self):
        result = mutate_null_byte("/etc/passwd")
        assert any("%00" in v for v in result)

    def test_mutate_unicode(self):
        result = mutate_unicode("<script>")
        assert len(result) > 0


class TestPayloadEvolutionEngine:
    def test_create(self):
        engine = PayloadEvolutionEngine()
        assert engine.max_mutations == 10

    def test_register_mutation_technique(self):
        engine = PayloadEvolutionEngine()
        engine.register_mutation_technique("custom", lambda p: [p + "!"])
        assert "custom" in engine.mutation_registry

    def test_evolve(self):
        engine = PayloadEvolutionEngine()
        payload = "<script>alert(1)</script>"
        candidates = engine.evolve(payload, "XSS")
        assert len(candidates) > 0
        assert all(c["category"] == "XSS" for c in candidates)

    def test_evolve_with_waf_context(self):
        engine = PayloadEvolutionEngine()
        candidates = engine.evolve("id", "RCE", context={"waf_detected": True})
        assert len(candidates) > 0

    def test_evolve_limits(self):
        engine = PayloadEvolutionEngine(max_mutations_per_payload=3)
        candidates = engine.evolve("test payload with spaces and <script>", "XSS")
        assert len(candidates) <= 3

    def test_record_result(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("test", "test", "LFI", success=True)
        assert len(engine.history) > 0

    def test_record_result_with_failure(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("test", "test", "LFI", success=False, blocked=True)
        score = engine.history.get(engine._hash("test"))
        assert score is not None
        assert score.waf_reaction > 0

    def test_rank_payloads(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("payload_a", "payload_a", "LFI", success=True, confidence=0.9)
        engine.record_result("payload_b", "payload_b", "LFI", success=False, confidence=0.1)

        payloads = [
            {"payload": "payload_a", "category": "LFI"},
            {"payload": "payload_b", "category": "LFI"},
            {"payload": "payload_c", "category": "LFI"},
        ]
        ranked = engine.rank_payloads(payloads)
        assert ranked[0]["payload"] == "payload_a"

    def test_rank_payloads_top_n(self):
        engine = PayloadEvolutionEngine()
        payloads = [
            {"payload": "a", "category": "LFI"},
            {"payload": "b", "category": "LFI"},
            {"payload": "c", "category": "LFI"},
        ]
        ranked = engine.rank_payloads(payloads, top_n=2)
        assert len(ranked) == 2

    def test_get_best_payload(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("best", "best", "XSS", success=True, confidence=0.95)
        engine.record_result("worst", "worst", "XSS", success=False, confidence=0.05)
        best = engine.get_best_payload("XSS")
        assert best is not None

    def test_get_best_payload_no_data(self):
        engine = PayloadEvolutionEngine()
        best = engine.get_best_payload("NONEXISTENT")
        assert best is None

    def test_get_evolution_summary(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("p1", "p1", "XSS", success=True)
        engine.record_result("p2", "p2", "LFI", success=False)
        summary = engine.get_evolution_summary()
        assert summary["total_payloads_tracked"] == 2
        assert "XSS" in summary["categories"]
        assert "LFI" in summary["categories"]

    def test_to_dict(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("test", "test", "RCE", success=True)
        d = engine.to_dict()
        assert "history" in d
        assert "summary" in d

    def test_to_json(self):
        engine = PayloadEvolutionEngine()
        engine.record_result("test", "test", "RCE", success=True)
        j = engine.to_json()
        parsed = json.loads(j)
        assert "history" in parsed
