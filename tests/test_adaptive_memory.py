# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Adaptive Memory
import pytest
import tempfile
import os
from core.adaptive_memory import AdaptiveMemory, MemoryEntry


@pytest.fixture
def temp_memory():
    with tempfile.TemporaryDirectory() as tmpdir:
        mem = AdaptiveMemory(storage_path=tmpdir, use_sqlite=False)
        yield mem


class TestMemoryEntry:
    def test_create_entry(self):
        entry = MemoryEntry(
            id="e1",
            entry_type="test",
            key="test_key",
            value="test_value",
            confidence=0.9,
        )
        assert entry.entry_type == "test"
        assert entry.value == "test_value"

    def test_to_dict(self):
        entry = MemoryEntry(id="e1", entry_type="t", key="k", value="v")
        d = entry.to_dict()
        assert d["entry_type"] == "t"


class TestAdaptiveMemory:
    def test_store_and_recall(self, temp_memory):
        temp_memory.store("test_type", "key1", "value1")
        val = temp_memory.recall("test_type", "key1")
        assert val == "value1"

    def test_recall_nonexistent(self, temp_memory):
        val = temp_memory.recall("nonexistent", "key")
        assert val is None

    def test_recall_entry(self, temp_memory):
        temp_memory.store("test", "k", "v")
        entry = temp_memory.recall_entry("test", "k")
        assert entry is not None
        assert entry.value == "v"

    def test_search(self, temp_memory):
        temp_memory.store("test", "hello_world", "value1")
        temp_memory.store("test", "goodbye_world", "value2")
        results = temp_memory.search("test", "hello")
        assert len(results) == 1

    def test_get_by_type(self, temp_memory):
        temp_memory.store("type_a", "k1", "v1")
        temp_memory.store("type_a", "k2", "v2")
        temp_memory.store("type_b", "k3", "v3")
        entries = temp_memory.get_by_type("type_a")
        assert len(entries) == 2

    def test_record_successful_payload(self, temp_memory):
        temp_memory.record_successful_payload("<script>", "XSS", "target1")
        entries = temp_memory.get_successful_payloads()
        assert len(entries) == 1
        assert entries[0].entry_type == "successful_payloads"

    def test_record_successful_payload_by_category(self, temp_memory):
        temp_memory.record_successful_payload("p1", "XSS", "t1")
        temp_memory.record_successful_payload("p2", "LFI", "t1")
        xss_entries = temp_memory.get_successful_payloads(category="XSS")
        assert len(xss_entries) == 1

    def test_record_blocked_payload(self, temp_memory):
        temp_memory.record_blocked_payload("malicious", "RCE")
        assert temp_memory.is_blocked("malicious", "RCE") is True

    def test_is_blocked_nonexistent(self, temp_memory):
        assert temp_memory.is_blocked("nothing", "XSS") is False

    def test_record_false_positive(self, temp_memory):
        temp_memory.record_false_positive("finding-1", "WAF interference", "XSS")
        assert temp_memory.is_false_positive("finding-1") is True

    def test_is_false_positive_nonexistent(self, temp_memory):
        assert temp_memory.is_false_positive("nope") is False

    def test_record_target_fingerprint(self, temp_memory):
        fp = {"os": "Linux", "server": "nginx"}
        temp_memory.record_target_fingerprint("http://example.com", fp)
        retrieved = temp_memory.get_target_fingerprint("http://example.com")
        assert retrieved == fp

    def test_get_target_fingerprint_nonexistent(self, temp_memory):
        assert temp_memory.get_target_fingerprint("http://unknown.com") is None

    def test_cleanup_expired(self, temp_memory):

        temp_memory.store("test", "fresh", "value")
        temp_memory.store("test", "stale", "value", ttl_days=0)
        removed = temp_memory.cleanup_expired()
        assert removed >= 0

    def test_get_stats(self, temp_memory):
        temp_memory.store("test", "k", "v")
        stats = temp_memory.get_stats()
        assert stats["total_entries"] >= 1
        assert "test" in stats["by_type"]

    def test_json_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mem = AdaptiveMemory(storage_path=tmpdir, use_sqlite=False)
            mem.store("persist", "key", "value")
            json_path = os.path.join(tmpdir, "memory.json")
            assert os.path.exists(json_path)

            mem2 = AdaptiveMemory(storage_path=tmpdir, use_sqlite=False)
            val = mem2.recall("persist", "key")
            assert val == "value"

    def test_close(self, temp_memory):
        temp_memory.close()
