# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parser regression framework.

When a parser changes, HunterX re-runs historical golden outputs and compares
observations, evidence, classification and confidence contribution. A golden
fixture pairs a raw tool output artifact with the expected canonical
observations after parsing + normalization.

The framework is tool-output driven: it replays stored raw artifacts through
registered parser/normalizer pairs without re-running the external binary.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from hunterx.tools.intelligence.normalizers import _parse_records

#: A parser maps raw output + metadata to a list of record mappings.
ParserFn = Callable[[Any, dict[str, Any]], list[dict[str, Any]]]
#: A normalizer maps a record + metadata to a canonical observation.
NormalizerFn = Callable[[dict[str, Any], dict[str, Any]], Any]


@dataclass(frozen=True, slots=True)
class GoldenFixture:
    """A golden parser regression fixture.

    Attributes:
        fixture_id: unique fixture identifier.
        tool_id: the tool the fixture covers.
        parser_id: parser identifier exercised.
        normalizer_id: normalizer identifier exercised.
        raw: the raw tool output artifact (string or list/dict).
        expected_observations: list of expected canonical observation values
            (each item is a dict of the observation's expected fields).
        metadata: parser metadata (tool version, target id, ...).
        description: human-readable description.

    """

    fixture_id: str
    tool_id: str
    parser_id: str
    normalizer_id: str
    raw: Any
    expected_observations: list[dict[str, Any]]
    metadata: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass(frozen=True, slots=True)
class RegressionReport:
    """Outcome of running a golden fixture through a parser/normalizer pair.

    Attributes:
        fixture_id: fixture identifier.
        tool_id: tool identifier.
        passed: whether the run matched expectations.
        observation_count: number of observations produced.
        expected_count: number of observations expected.
        missing_values: expected values not observed.
        unexpected_values: observed values not expected.
        produced: serialized observations produced.
        error: parse/normalize error message when the run failed.

    """

    fixture_id: str
    tool_id: str
    passed: bool
    observation_count: int = 0
    expected_count: int = 0
    missing_values: tuple[str, ...] = ()
    unexpected_values: tuple[str, ...] = ()
    produced: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


class ParserRegressionEngine:
    """Run golden fixtures through parser/normalizer pairs and compare.

    Usage::

        engine = ParserRegressionEngine()
        engine.register("json", _parse_records, normalizer)
        report = engine.run(fixture)
    """

    def __init__(self) -> None:
        self._parsers: dict[str, ParserFn] = {}
        self._normalizers: dict[str, NormalizerFn] = {}
        self._metadata: dict[str, dict[str, Any]] = {}

    def register(
        self,
        parser_id: str,
        parser: ParserFn,
        normalizer_id: str | None = None,
        normalizer: NormalizerFn | None = None,
    ) -> None:
        """Register a parser and optional normalizer under ``parser_id``.

        When ``parser_id`` equals ``normalizer_id`` and only one is given, the
        same callable is used for both.
        """
        self._parsers[parser_id] = parser
        normalizer_id = normalizer_id or parser_id
        if normalizer is None:
            normalizer = parser  # type: ignore[assignment]
        self._normalizers[normalizer_id] = normalizer
        self._metadata.setdefault(parser_id, {})["normalizer_id"] = normalizer_id

    def register_builtin(self) -> None:
        """Register the TIP built-in JSON/JSONL/text parser and normalizers."""
        self._parsers["json"] = _parse_records
        self._parsers["jsonl"] = _parse_records
        self._parsers["text"] = _parse_records

    def run(self, fixture: GoldenFixture) -> RegressionReport:
        """Run ``fixture`` and compare produced observations with expectations."""
        parser = self._parsers.get(fixture.parser_id)
        if parser is None:
            return RegressionReport(
                fixture.fixture_id,
                fixture.tool_id,
                False,
                error=f"no parser registered for '{fixture.parser_id}'",
            )
        normalizer_id = fixture.normalizer_id or self._metadata.get(fixture.parser_id, {}).get(
            "normalizer_id", fixture.parser_id
        )
        normalizer = self._normalizers.get(normalizer_id)
        metadata = dict(fixture.metadata)
        metadata["tool_id"] = fixture.tool_id

        try:
            records = parser(fixture.raw, metadata)
            produced: list[dict[str, Any]] = []
            if normalizer is not None:
                for record in records:
                    observation = normalizer(record, metadata)
                    produced.append(_observation_to_dict(observation))
            else:
                produced = [dict(record) for record in records]
        except Exception as exc:  # noqa: BLE001 - regression must never raise
            return RegressionReport(
                fixture.fixture_id,
                fixture.tool_id,
                False,
                error=str(exc),
            )

        return _compare(fixture, produced)

    def run_many(self, fixtures: list[GoldenFixture]) -> list[RegressionReport]:
        """Run several fixtures and return all reports."""
        return [self.run(fixture) for fixture in fixtures]

    def passed(self, fixtures: list[GoldenFixture]) -> bool:
        """Return ``True`` when every fixture passed."""
        return all(report.passed for report in self.run_many(fixtures))


def _compare(fixture: GoldenFixture, produced: list[dict[str, Any]]) -> RegressionReport:
    """Compare produced observations against expected ones."""
    expected = fixture.expected_observations
    expected_values = {_observation_key(item) for item in expected}
    produced_values = {_observation_key(item) for item in produced}
    missing = tuple(sorted(expected_values - produced_values))
    unexpected = tuple(sorted(produced_values - expected_values))
    return RegressionReport(
        fixture_id=fixture.fixture_id,
        tool_id=fixture.tool_id,
        passed=not missing and not unexpected,
        observation_count=len(produced),
        expected_count=len(expected),
        missing_values=missing,
        unexpected_values=unexpected,
        produced=produced,
    )


def _observation_key(item: dict[str, Any]) -> str:
    """Build a comparison key for an observation dict."""
    kind = str(item.get("observation_kind") or item.get("kind") or "")
    value = str(item.get("normalized_value") or item.get("value") or item.get("name") or "")
    return f"{kind}:{value}"


def _observation_to_dict(observation: Any) -> dict[str, Any]:
    """Serialize a canonical observation (or dataclass) to a dict."""
    if isinstance(observation, dict):
        return dict(observation)
    if hasattr(observation, "observation_kind"):
        return {
            "observation_kind": observation.observation_kind,
            "value": observation.value,
            "normalized_value": observation.normalized_value,
            "confidence": observation.confidence,
            "correlation_key": observation.correlation_key,
        }
    return {"value": str(observation)}
