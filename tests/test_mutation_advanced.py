import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.mutation_engine import MutationEngine


def test_json_mutations():
    me = MutationEngine("high")
    variants = me.mutate("test' OR 1=1--", "SQLI")
    techniques = {v["technique"] for v in variants}
    assert "json_escape" in techniques or "json_wrap_object" in techniques


def test_multipart_mutations():
    me = MutationEngine("high")
    variants = me.mutate("test", "GENERIC")
    techniques = {v["technique"] for v in variants}
    assert "multipart_form" in techniques


def test_chunked_mutations():
    me = MutationEngine("high")
    variants = me.mutate("test", "GENERIC")
    techniques = {v["technique"] for v in variants}
    assert "chunked_encoding" in techniques


def test_graphql_mutations():
    me = MutationEngine("high")
    variants = me.mutate("test", "GENERIC")
    techniques = {v["technique"] for v in variants}
    assert any("graphql" in t for t in techniques)


def test_websocket_mutations():
    me = MutationEngine("high")
    variants = me.mutate("test", "GENERIC")
    techniques = {v["technique"] for v in variants}
    assert any("websocket" in t for t in techniques)


def test_whitespace_injections():
    me = MutationEngine("high")
    variants = me.mutate("SELECT 1 FROM users", "SQLI")
    techniques = {v["technique"] for v in variants}
    assert any("whitespace" in t or "tab" in t or "crlf" in t for t in techniques)


def test_sql_case_mutations():
    me = MutationEngine("high")
    variants = me.mutate("select * from users", "SQLI")
    techniques = {v["technique"] for v in variants}
    assert "sql_case_mutation" in techniques or "sql_upper" in techniques


def test_html_entity_mutations():
    me = MutationEngine("high")
    variants = me.mutate("<script>alert(1)</script>", "XSS")
    techniques = {v["technique"] for v in variants}
    assert "html_entity" in techniques


def test_unicode_normalize():
    me = MutationEngine("high")
    variants = me.mutate("<test>", "XSS")
    techniques = {v["technique"] for v in variants}
    assert "unicode_encode" in techniques


def test_advanced_mutations():
    me = MutationEngine("high")
    variants = me.mutate_advanced("../../../etc/passwd", "LFI")
    assert len(variants) > 5
    techniques = {v["technique"] for v in variants}
    assert "original" in techniques


def test_low_evasion_no_advanced():
    me = MutationEngine("low")
    variants = me.mutate("test", "GENERIC")
    techniques = {v["technique"] for v in variants}
    assert len(variants) == 1
    assert "original" in techniques
