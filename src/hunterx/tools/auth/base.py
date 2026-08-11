# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for authentication intelligence tools.

Every authentication intelligence adapter implements the SDK
:class:`ToolAdapter` lifecycle and shares this base. Authentication analysis is
an in-process, intelligence-only capability: the adapter receives already-
acquired static material (HTTP snapshot, script content, API security schemes,
documents, TIDB intelligence) through the execution parameters — never
authenticates, never validates tokens — runs the domain analyzer and serializes
the canonical observations into the pipeline's JSON payload under the ``auth``
key exactly as :func:`~hunterx.domain.auth.models.observations_from_payload`
expects.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.auth.models import (
    FINDINGS_KEY,
    AuthInput,
    record_to_dict,
)
from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class AuthToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for in-process authentication intelligence adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`analyze`,
    which runs the domain analyzer over one :class:`AuthInput` and returns the
    list of canonical observations. The default :meth:`run` builds the input
    from the execution parameters, records the analysis and writes the
    normalized JSON payload.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required for in-process analyzers; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    @abc.abstractmethod
    def analyze(self, bundle: AuthInput) -> list[Any]:
        """Analyze one input bundle and return the canonical observations."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Build the :class:`AuthInput` and emit the auth payload."""
        params = context.parameters or {}
        bundle = self._bundle(context, params)
        observations = self.analyze(bundle)
        entries = [record_to_dict(observation) for observation in observations]
        collector.set_exit_code(0)
        collector.set_json({FINDINGS_KEY: entries, "count": len(entries)})

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project auth observations into the canonical tool output."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get(FINDINGS_KEY), list):
            entries = [entry for entry in payload[FINDINGS_KEY] if isinstance(entry, dict)]
            tool_output.assets = [entry for entry in entries if entry.get("type") in ("auth-surface", "auth-endpoint")]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- input construction -------------------------------------------------

    def _bundle(self, context: ExecutionContext, params: dict[str, Any]) -> AuthInput:
        raw = params.get("auth_input")
        if isinstance(raw, dict):
            return _bundle_from_mapping(raw, context)
        return AuthInput(
            target=context.target,
            url=_param_str(params.get("url")),
            status_code=_param_int(params.get("status_code")),
            headers=_param_pairs(params.get("headers")),
            cookies=_param_cookies(params.get("cookies")),
            html=_param_str(params.get("html")),
            content_type=_param_str(params.get("content_type")),
            final_url=_param_str(params.get("final_url")),
            scripts=_param_scripts(params.get("scripts")),
            api_schemes=_param_records(params.get("api_schemes")),
            documents=_param_records(params.get("documents")),
            observed_urls=_param_str_list(params.get("observed_urls")),
            tidb_hints=_param_records(params.get("tidb_hints")),
            source=_param_str(params.get("source"), "auth"),
            tool_id=context.tool_id,
        )


def _bundle_from_mapping(raw: dict[str, Any], context: ExecutionContext) -> AuthInput:
    """Rebuild an :class:`AuthInput` from a serialized mapping."""
    return AuthInput(
        target=_param_str(raw.get("target"), context.target),
        url=_param_str(raw.get("url")),
        status_code=_param_int(raw.get("status_code")),
        headers=_param_pairs(raw.get("headers")),
        cookies=_param_cookies(raw.get("cookies")),
        html=_param_str(raw.get("html")),
        content_type=_param_str(raw.get("content_type")),
        final_url=_param_str(raw.get("final_url")),
        scripts=_param_scripts(raw.get("scripts")),
        api_schemes=_param_records(raw.get("api_schemes")),
        documents=_param_records(raw.get("documents")),
        observed_urls=_param_str_list(raw.get("observed_urls")),
        tidb_hints=_param_records(raw.get("tidb_hints")),
        source=_param_str(raw.get("source"), "auth"),
        tool_id=_param_str(raw.get("tool_id"), context.tool_id),
    )


def _param_str(value: object, default: str = "") -> str:
    if isinstance(value, str):
        return value
    return str(value) if value is not None else default


def _param_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _param_pairs(value: object) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        pairs.extend((str(key), str(item)) for key, item in value.items())
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, dict) and "name" in item and "value" in item:
                pairs.append((str(item["name"]), str(item["value"])))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((str(item[0]), str(item[1])))
    return tuple(pairs)


def _param_cookies(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, dict))


def _param_scripts(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    scripts: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            scripts.append((_param_str(item.get("url")), _param_str(item.get("content"))))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            scripts.append((_param_str(item[0]), _param_str(item[1])))
    return tuple(scripts)


def _param_records(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(dict(item) for item in value if isinstance(item, dict))


def _param_str_list(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if item is not None)
    return ()
