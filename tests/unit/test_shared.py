# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared foundation layer."""

from __future__ import annotations

import pytest

from hunterx.shared.di import Container
from hunterx.shared.ids import generate_content_id, generate_id, is_ulid
from hunterx.shared.masking import MaskConfig, mask_secret, mask_value
from hunterx.shared.result import Failure, Success


class TestIds:
    def test_generate_id_is_ulid_format(self) -> None:
        value = generate_id()
        assert len(value) == 26
        assert is_ulid(value)

    def test_ids_are_unique(self) -> None:
        first = generate_id()
        second = generate_id()
        assert first != second

    def test_content_hash_is_stable(self) -> None:
        assert generate_content_id("a", 1, True) == generate_content_id("a", 1, True)

    def test_content_hash_changes_with_input(self) -> None:
        assert generate_content_id("a") != generate_content_id("b")

    def test_content_hash_normalizes_none_and_false(self) -> None:
        assert generate_content_id("x", None, False) == generate_content_id("x", None, None)


class TestMasking:
    def test_mask_value_keeps_edges(self) -> None:
        assert mask_value("abcdefgh") == "a******h"

    def test_mask_value_short_string(self) -> None:
        assert mask_value("ab") == "**"

    def test_mask_secret_uses_config(self) -> None:
        assert mask_secret("supersecret", MaskConfig(reveal_head=2, reveal_tail=2)) == "su*******et"

    def test_mask_value_empty(self) -> None:
        assert mask_value("") == ""


class TestResult:
    def test_success_ok(self) -> None:
        assert Success(1).ok is True
        assert Success(1).value == 1

    def test_failure_ok(self) -> None:
        assert Failure(ValueError("nope")).ok is False
        assert isinstance(Failure(ValueError("nope")).error, ValueError)


class TestContainer:
    def test_resolve_factory(self) -> None:
        container = Container()
        container.register(dict, lambda _c: {"n": 1})
        assert container.resolve(dict) == {"n": 1}

    def test_singleton_cached(self) -> None:
        container = Container()
        calls = 0

        def factory(_container: object) -> list[int]:
            nonlocal calls
            calls += 1
            return [calls]

        container.register(list, factory, singleton=True)
        assert container.resolve(list) == [1]
        assert container.resolve(list) == [1]
        assert calls == 1

    def test_duplicate_registration_raises(self) -> None:
        container = Container()
        container.register(dict, lambda _c: {})
        with pytest.raises(Exception):
            container.register(dict, lambda _c: {})

    def test_registration_not_found(self) -> None:
        container = Container()
        with pytest.raises(Exception):
            container.resolve(dict)

    def test_parent_fallback(self) -> None:
        parent = Container()
        parent.register(str, lambda _c: "parent")
        child = Container(parent=parent)
        assert child.resolve(str) == "parent"
