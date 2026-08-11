# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence tool adapter base.

The :class:`CloudToolAdapter` extends the Tool Integration SDK
:class:`ToolAdapter` contract with an ``analyze(bundle)`` seam. The shared
``run`` implementation builds a :class:`CloudInput` bundle from the execution
parameters, runs the analyzer and serialises the typed observations under the
``cloud`` payload key.
"""

from __future__ import annotations

import abc
from collections.abc import Mapping
from typing import Any

from hunterx.domain.cloud.models import (
    FINDINGS_KEY,
    CloudInput,
    record_to_dict,
)
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter


class CloudToolAdapter(ToolAdapter, abc.ABC):
    """Base adapter for cloud & SaaS intelligence tools.

    Subclasses set a static ``descriptor`` and implement :meth:`analyze`, which
    returns the typed observations the run should persist.
    """

    descriptor: ToolDescriptor

    @abc.abstractmethod
    def analyze(self, bundle: CloudInput) -> list[Any]:
        """Analyze a bundle and return typed cloud observations."""

    def prepare(self, context: Any) -> None:  # noqa: D102 - parity hook
        pass

    def cleanup(self, context: Any) -> None:  # noqa: D102 - parity hook
        pass

    def run(self, context: Any, collector: Any) -> None:
        """Run the analyzer and write typed observations to the collector."""
        params = context.parameters or {}
        bundle = self._bundle(context, params)
        observations = self.analyze(bundle)
        entries = [record_to_dict(observation) for observation in observations]
        collector.set_exit_code(0)
        collector.set_json({FINDINGS_KEY: entries, "count": len(entries)})

    def validate_output(self, context: Any, output: Any) -> tuple[bool, list[str]]:
        """Treat any non-zero exit as invalid; empty observation sets are valid."""
        if output.exit_code != 0:
            return False, [f"cloud tool exited with code {output.exit_code}"]
        return True, []

    def normalize(self, context: Any, output: Any) -> ToolOutput:
        """Project the raw output onto the canonical :class:`ToolOutput`."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        if output.json and isinstance(output.json.get(FINDINGS_KEY), list):
            entries = [entry for entry in output.json[FINDINGS_KEY] if isinstance(entry, dict)]
            tool_output.assets = [
                entry for entry in entries if entry.get("type") in ("cloud-resource", "cloud-endpoint")
            ]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    def _bundle(self, context: Any, params: Mapping[str, Any]) -> CloudInput:
        """Build a :class:`CloudInput` from a serialized bundle or discrete params."""
        payload = params.get("cloud_input")
        if isinstance(payload, dict):
            return _bundle_from_mapping(context, payload)
        return CloudInput(
            target=str(params.get("target") or context.target or ""),
            domain=str(params.get("domain") or ""),
            records=_param_records(params.get("records")),
            certificates=_param_records(params.get("certificates")),
            headers=_param_pairs(params.get("headers")),
            html=str(params.get("html") or ""),
            scripts=_param_scripts(params.get("scripts")),
            api_schemes=_param_records(params.get("api_schemes")),
            documents=_param_records(params.get("documents")),
            technologies=_param_records(params.get("technologies")),
            observed_urls=tuple(str(item) for item in params.get("observed_urls") or ()),
            tidb_hints=_param_records(params.get("tidb_hints")),
            source="cloud",
            tool_id=context.tool_id,
        )


def _bundle_from_mapping(context: Any, payload: Mapping[str, Any]) -> CloudInput:
    """Build a :class:`CloudInput` from a pre-serialized mapping."""
    return CloudInput(
        target=str(payload.get("target") or context.target or ""),
        domain=str(payload.get("domain") or ""),
        records=_param_records(payload.get("records")),
        certificates=_param_records(payload.get("certificates")),
        headers=_param_pairs(payload.get("headers")),
        html=str(payload.get("html") or ""),
        scripts=_param_scripts(payload.get("scripts")),
        api_schemes=_param_records(payload.get("api_schemes")),
        documents=_param_records(payload.get("documents")),
        technologies=_param_records(payload.get("technologies")),
        observed_urls=tuple(str(item) for item in payload.get("observed_urls") or ()),
        tidb_hints=_param_records(payload.get("tidb_hints")),
        source=str(payload.get("source") or "cloud"),
        tool_id=str(payload.get("tool_id") or context.tool_id),
    )


def collector_duration_ms(output: Any) -> int:
    """Return the collection duration when the collector exposed it."""
    return int(getattr(output, "duration_ms", 0) or 0)


def _param_records(value: Any) -> tuple[dict[str, Any], ...]:
    """Coerce a parameter into a tuple of dictionaries."""
    if value is None:
        return ()
    if isinstance(value, dict):
        return (dict(value),)
    if isinstance(value, (list, tuple)):
        records: list[dict[str, Any]] = []
        for item in value:
            if isinstance(item, dict):
                records.append(dict(item))
            elif hasattr(item, "to_dict"):
                records.append(item.to_dict())
        return tuple(records)
    return ()


def _param_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    """Coerce a parameter into header-style (name, value) pairs."""
    if value is None:
        return ()
    if isinstance(value, dict):
        pairs: list[tuple[str, str]] = []
        for key, item in value.items():
            if isinstance(item, list):
                pairs.extend((str(key), str(sub)) for sub in item)
            else:
                pairs.append((str(key), str(item)))
        return tuple(pairs)
    if isinstance(value, (list, tuple)):
        pairs = []
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((str(item[0]), str(item[1])))
            elif isinstance(item, dict) and "name" in item:
                pairs.append((str(item["name"]), str(item.get("value") or "")))
        return tuple(pairs)
    return ()


def _param_scripts(value: Any) -> tuple[tuple[str, str], ...]:
    """Coerce a parameter into (url, content) script pairs."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        scripts: list[tuple[str, str]] = []
        for item in value:
            if isinstance(item, dict):
                scripts.append((str(item.get("url") or ""), str(item.get("content") or "")))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                scripts.append((str(item[0]), str(item[1])))
        return tuple(scripts)
    return ()
