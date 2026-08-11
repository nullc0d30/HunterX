# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parser and normalizer registries.

Sprint 023 introduces structured, typed output handling: every tool declares a
``parser_id`` and ``normalizer_id`` in its knowledge profile, and the platform
looks the actual callables up in these registries. A parser turns raw tool
output into structured records; a normalizer turns those records into
canonical observations (:class:`CanonicalObservation`).

The registries are deliberately decoupled from the SDK execution pipeline so
the Tool Intelligence Layer can validate parser/normalizer references at
registration time and resolve them lazily at execution time.
"""

from __future__ import annotations

from collections.abc import Callable
from threading import RLock
from typing import Any, TypeAlias

from hunterx.domain.exceptions import ConfigurationError
from hunterx.domain.tool_intelligence import CanonicalObservation

#: A parser turns raw text/structured output into a list of raw records.
ParserFunction: TypeAlias = Callable[[Any, dict[str, Any]], list[dict[str, Any]]]

#: A normalizer turns parsed records into canonical observations.
NormalizerFunction: TypeAlias = Callable[[dict[str, Any], dict[str, Any]], CanonicalObservation]

#: Canonical parser identifiers built into the platform.
BUILTIN_PARSERS: tuple[str, ...] = ("json", "jsonl", "text", "xml", "raw")

#: Canonical normalizer identifiers built into the platform.
BUILTIN_NORMALIZERS: tuple[str, ...] = ("default", "domain", "url", "ip", "port", "technology")


class ParserRegistry:
    """Thread-safe registry mapping ``parser_id`` → parser callable.

    Parser signatures: ``parser(raw_output, metadata) -> list[dict]`` where
    ``metadata`` is the tool's knowledge profile (as a mapping) and each
    returned dict is one raw record.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._parsers: dict[str, ParserFunction] = {}

    def register(self, parser_id: str, parser: ParserFunction) -> None:
        """Register a parser under ``parser_id`` (lowercased)."""
        key = parser_id.lower()
        with self._lock:
            self._parsers[key] = parser

    def get(self, parser_id: str) -> ParserFunction | None:
        """Return the parser for ``parser_id`` or ``None``."""
        with self._lock:
            return self._parsers.get(parser_id.lower())

    def require(self, parser_id: str) -> ParserFunction:
        """Return the parser for ``parser_id``, raising when unknown."""
        parser = self.get(parser_id)
        if parser is None:
            raise ConfigurationError(f"unknown parser id '{parser_id}'")
        return parser

    def known(self) -> tuple[str, ...]:
        """Return the sorted known parser ids."""
        with self._lock:
            return tuple(sorted(self._parsers))

    def register_builtin(self) -> None:
        """Register the built-in passthrough/JSON-style parsers."""
        from hunterx.tools.intelligence.normalizers import _parse_records

        for parser_id in BUILTIN_PARSERS:
            if self.get(parser_id) is None:
                self.register(parser_id, _parse_records)


class NormalizerRegistry:
    """Thread-safe registry mapping ``normalizer_id`` → normalizer callable.

    Normalizer signatures: ``normalizer(record, metadata) -> CanonicalObservation``.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._normalizers: dict[str, NormalizerFunction] = {}

    def register(self, normalizer_id: str, normalizer: NormalizerFunction) -> None:
        """Register a normalizer under ``normalizer_id`` (lowercased)."""
        key = normalizer_id.lower()
        with self._lock:
            self._normalizers[key] = normalizer

    def get(self, normalizer_id: str) -> NormalizerFunction | None:
        """Return the normalizer for ``normalizer_id`` or ``None``."""
        with self._lock:
            return self._normalizers.get(normalizer_id.lower())

    def require(self, normalizer_id: str) -> NormalizerFunction:
        """Return the normalizer for ``normalizer_id``, raising when unknown."""
        normalizer = self.get(normalizer_id)
        if normalizer is None:
            raise ConfigurationError(f"unknown normalizer id '{normalizer_id}'")
        return normalizer

    def known(self) -> tuple[str, ...]:
        """Return the sorted known normalizer ids."""
        with self._lock:
            return tuple(sorted(self._normalizers))

    def register_builtin(self) -> None:
        """Register the built-in canonical normalizers."""
        from hunterx.tools.intelligence.normalizers import (
            _normalize_domain,
            _normalize_ip,
            _normalize_port,
            _normalize_technology,
            _normalize_url,
        )

        builtins: dict[str, NormalizerFunction] = {
            "default": _normalize_default,
            "domain": _normalize_domain,
            "url": _normalize_url,
            "ip": _normalize_ip,
            "port": _normalize_port,
            "technology": _normalize_technology,
        }
        for normalizer_id, fn in builtins.items():
            if self.get(normalizer_id) is None:
                self.register(normalizer_id, fn)


class ToolRuntimeRegistry:
    """Composed parser + normalizer registries with knowledge lookups.

    Provides the single entry point the layer uses to resolve the parser and
    normalizer declared by a tool's knowledge profile.
    """

    def __init__(
        self,
        parsers: ParserRegistry | None = None,
        normalizers: NormalizerRegistry | None = None,
    ) -> None:
        self.parsers = parsers or ParserRegistry()
        self.normalizers = normalizers or NormalizerRegistry()

    def ensure_builtins(self) -> None:
        """Register the built-in parsers and normalizers (idempotent)."""
        self.parsers.register_builtin()
        self.normalizers.register_builtin()

    def resolve(self, parser_id: str, normalizer_id: str) -> tuple[ParserFunction, NormalizerFunction]:
        """Return ``(parser, normalizer)`` for the given ids.

        Raises:
            ConfigurationError: if either id is not registered.

        """
        return self.parsers.require(parser_id), self.normalizers.require(normalizer_id)


def _normalize_default(record: dict[str, Any], metadata: dict[str, Any]) -> CanonicalObservation:
    """Normalize a record into a generic observation using knowledge defaults."""
    tool_id = str(metadata.get("tool_id", ""))
    target_id = str(record.get("target_id") or metadata.get("target_id", ""))
    kind = str(record.get("observation_kind") or record.get("kind") or "other")
    return CanonicalObservation(
        observation_id=str(record.get("observation_id") or ""),
        target_id=target_id,
        tool_id=tool_id,
        observation_kind=kind,
        value=str(record.get("value", "")),
        normalized_value=str(record.get("normalized_value", "")),
        asset_id=str(record.get("asset_id", "")),
        tool_version=str(metadata.get("tool_version", "")),
        confidence=float(record.get("confidence", 1.0)),
        timestamp=str(record.get("timestamp", "")),
        source=str(record.get("source", tool_id)),
        raw_artifact_reference=str(record.get("raw_artifact_reference", "")),
        correlation_key=str(record.get("correlation_key", "")),
        provenance=dict(record.get("provenance") or {}),
    )
