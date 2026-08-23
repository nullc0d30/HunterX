# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the canonical JSON-safe serialization boundary.

Covers the persistence contract: every value that may enter a JSON-backed
column must survive :func:`hunterx.shared.json_safe.to_json_safe` as strict,
JSON-native data with its semantics preserved.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import math
import uuid
from enum import Enum
from pathlib import Path

import pytest

from hunterx.domain.javascript.tokenizer import JSToken, JSTokenType
from hunterx.shared.json_safe import safe_repr, to_json_safe


class Color(Enum):
    RED = "red"


@dataclasses.dataclass(frozen=True)
class Point:
    x: int
    y: int


class Opaque:
    """Custom object with no structured accessors."""


class Structured:
    def __init__(self) -> None:
        self.name = "surface"
        self.score = 0.5

    def to_dict(self) -> dict:
        return {"name": self.name, "score": self.score}


def dumps(value: object) -> str:
    return json.dumps(value)


def test_primitives_pass_through_exactly() -> None:
    assert to_json_safe(None) is None
    assert to_json_safe(True) is True
    assert to_json_safe(False) is False
    assert to_json_safe(123) == 123
    assert to_json_safe(1.5) == 1.5
    assert to_json_safe("abc") == "abc"


def test_nested_dict_with_custom_object_is_serializable() -> None:
    payload = {"a": 1, "b": JSToken(token_type=JSTokenType.IDENTIFIER, value="fetch")}
    safe = to_json_safe(payload)
    assert json.loads(dumps(safe))["b"]["__type__"] == "JSToken"
    assert safe["b"]["token_type"] == "identifier"
    assert safe["b"]["value"] == "fetch"


def test_list_tuple_set_recursed() -> None:
    safe = to_json_safe([1, (2, 3), {Point(1, 2)}])
    assert isinstance(safe, list)
    assert safe[0] == 1 and safe[1] == [2, 3]
    assert safe[2]["__type__"] == "set"
    items = safe[2]["items"]
    assert items == [{"__type__": "Point", "x": 1, "y": 2}]


def test_dataclass_expanded_structurally() -> None:
    safe = to_json_safe(Point(x=3, y=4))
    assert safe == {"__type__": "Point", "x": 3, "y": 4}
    json.loads(dumps(safe))


def test_enum_preserves_semantic_value() -> None:
    assert to_json_safe(Color.RED) == "red"
    assert to_json_safe(JSTokenType.TEMPLATE) == "template"


def test_datetime_date_time_isoformat() -> None:
    stamp = dt.datetime(2026, 8, 23, 12, 30, 45, tzinfo=dt.UTC)
    assert to_json_safe(stamp) == "2026-08-23T12:30:45+00:00"
    assert to_json_safe(dt.date(2026, 8, 23)) == "2026-08-23"
    assert to_json_safe(dt.time(1, 2, 3)) == "01:02:03"


def test_uuid_stringified() -> None:
    value = uuid.UUID("12345678-1234-5678-1234-567812345678")
    assert to_json_safe(value) == "12345678-1234-5678-1234-567812345678"


def test_path_stringified() -> None:
    assert to_json_safe(Path("hunterx.db")) == "hunterx.db"


def test_custom_object_uses_structured_accessor() -> None:
    safe = to_json_safe(Structured())
    assert safe == {"__type__": "Structured", "name": "surface", "score": 0.5}


def test_opaque_object_typed_repr_without_memory_address() -> None:
    safe = to_json_safe(Opaque())
    assert safe["__type__"] == "Opaque"
    assert "repr" in safe
    assert "0x" not in dumps(safe)


def test_js_token_full_semantics_preserved() -> None:
    token = JSToken(
        token_type=JSTokenType.STRING,
        value="/api/login",
        line=7,
        column=13,
        offset=120,
        raw='"/api/login"',
    )
    safe = to_json_safe(token)
    assert safe == {
        "__type__": "JSToken",
        "token_type": "string",
        "value": "/api/login",
        "line": 7,
        "column": 13,
        "offset": 120,
        'raw': '"/api/login"',
    }
    json.loads(dumps(safe))


def test_nested_js_token_inside_deep_payload() -> None:
    payload = {
        "javascript": {
            "analyses": [
                {
                    "endpoints": [
                        {"url": "/api/login", "evidence": [JSToken(JSTokenType.STRING, "/api/login", 3, 9, 40)]}
                    ]
                }
            ]
        }
    }
    safe = to_json_safe(payload)
    leaf = safe["javascript"]["analyses"][0]["endpoints"][0]["evidence"][0]
    assert leaf["__type__"] == "JSToken" and leaf["value"] == "/api/login"
    json.loads(dumps(safe))


def test_circular_reference_terminates() -> None:
    payload: dict = {"name": "cycle"}
    payload["self"] = payload
    safe = to_json_safe(payload)
    assert safe["name"] == "cycle"
    assert safe["self"] == {"__circular__": True}
    json.loads(dumps(safe))


def test_self_referencing_list() -> None:
    chain: list = [1]
    chain.append(chain)
    safe = to_json_safe(chain)
    assert safe[0] == 1
    assert safe[1] == {"__circular__": True}
    json.loads(dumps(safe))


def test_non_string_keys_deterministic_no_collisions() -> None:
    payload = {1: "int", "1": "str", None: "none", (2, 3): "tuple"}
    safe = to_json_safe(payload)
    assert len(safe) == 4
    assert safe["1"] == "int"
    assert safe["1#1"] == "str"
    assert safe["null"] == "none"
    json.loads(dumps(safe))
    # deterministic across calls
    assert to_json_safe(payload) == safe


def test_nan_and_infinity_valid_strict_json() -> None:
    safe = to_json_safe({"nan": float("nan"), "pos": float("inf"), "neg": float("-inf")})
    text = dumps(safe)
    assert "NaN" not in text.replace('"NaN"', "")
    assert json.loads(text) == {"nan": "NaN", "pos": "Infinity", "neg": "-Infinity"}
    assert not math.isfinite(float("nan"))


def test_secret_like_keys_masked() -> None:
    payload = {
        "password": "hunter2-secret",
        "Authorization": "Bearer abc.def.ghi",
        "api_key": "sk-live-abcdef",
        "cookie": "session=zzz",
        "normal": "visible",
    }
    safe = to_json_safe(payload)
    assert "hunter2-secret" not in dumps(safe)
    assert "abc.def.ghi" not in dumps(safe)
    assert "sk-live-abcdef" not in dumps(safe)
    assert "session=zzz" not in dumps(safe)
    assert safe["normal"] == "visible"
    # head/tail hint preserved for operators
    assert safe["password"].startswith("h") and safe["password"].endswith("t")


def test_secret_values_not_leaked_through_nested_objects() -> None:
    class Credentials:
        def __init__(self) -> None:
            self.password = "topsecret"

    safe = to_json_safe({"auth": Credentials()})
    text = dumps(safe)
    assert "topsecret" not in text
    # generic object attrs are NOT masked per-key; ensure the marker keeps type info
    assert safe["auth"]["__type__"] == "Credentials"


def test_already_json_safe_payload_semantically_identical() -> None:
    payload = {
        "mission_id": "m1",
        "scores": [0.25, 0.5, 1.0],
        "nested": {"flag": False, "empty": None, "tags": ["a", "b"]},
    }
    assert to_json_safe(payload) == payload


def test_input_objects_never_mutated() -> None:
    token = JSToken(JSTokenType.STRING, "/x", 1, 1, 0, '"/x"')
    payload = {"tokens": [token]}
    original = repr(payload)
    to_json_safe(payload)
    assert repr(payload) == original


def test_safe_repr_strips_addresses() -> None:
    text = safe_repr(Opaque())
    assert "0x" not in text
    assert "Opaque" in text


def test_bytes_typed_preview() -> None:
    safe = to_json_safe({"blob": b"\xff\xfebinary"})
    entry = safe["blob"]
    assert entry["__type__"] == "bytes" and entry["size"] == 8
    json.loads(dumps(safe))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ([], []),
        ({}, {}),
        (("a",), ["a"]),
        (frozenset(), {"__type__": "set", "items": []}),
    ],
)
def test_empty_containers(value: object, expected: object) -> None:
    assert to_json_safe(value) == expected
