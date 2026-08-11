# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge dataset adapters.

Integrates the passive knowledge datasets — PayloadsAllTheThings, SecLists and
FuzzDB — into the Tool Integration SDK as in-process reference providers.

Datasets are knowledge, not executable truth: the adapter exposes a bounded
description (name, version, path, entry count, category) for operator use and
never auto-executes payloads or wordlist contents. Payload/wordlist material is
consumed as data by the tools that request it under explicit authorization.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class KnowledgeDatasetAdapter(ToolAdapter):
    """In-process adapter exposing a passive knowledge dataset."""

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    #: Dataset name reported in the output payload.
    dataset_name: str = ""

    #: Dataset category reported in the output payload.
    dataset_category: str = ""

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Expose the dataset reference and a bounded entry preview."""
        params = context.parameters or {}
        path = str(params.get("path") or "")
        preview = _preview(params.get("preview"), 20)
        collector.set_exit_code(0)
        collector.set_json(
            {
                "datasets": {
                    "name": self.dataset_name,
                    "category": self.dataset_category,
                    "path": path,
                    "version": str(params.get("version") or self.descriptor.version),
                    "entry_count": _entry_count(params.get("entry_count")),
                    "preview": preview,
                    "tool_id": context.tool_id,
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            }
        )

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; a dataset reference is always valid."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project the dataset reference into the legacy asset surface."""
        tool_output = ToolOutput()
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("datasets"), dict):
            tool_output.assets = [dict(payload["datasets"])]
        return tool_output


class PayloadsAllTheThingsAdapter(KnowledgeDatasetAdapter):
    """SDK adapter for the PayloadsAllTheThings payload knowledge base."""

    dataset_name = "PayloadsAllTheThings"
    dataset_category = "payload"

    descriptor = ToolDescriptor(
        name="payloadsallthethings",
        version="2024-01-01",
        description="Payload knowledge base for web exploitation techniques (reference only).",
        entrypoint="hunterx.tools.knowledge.adapters:PayloadsAllTheThingsAdapter",
        targets=("knowledge",),
        capabilities=("payload-intelligence", "attack-patterns", "payload-generation"),
        permissions=(),
        parameters={
            "path": {"type": "string", "description": "Local checkout path of the dataset."},
            "preview": {"type": "array", "description": "Bounded preview entries."},
            "entry_count": {"type": "integer", "description": "Total entry count."},
        },
    )


class SeclistsAdapter(KnowledgeDatasetAdapter):
    """SDK adapter for the SecLists wordlist collection."""

    dataset_name = "SecLists"
    dataset_category = "wordlist"

    descriptor = ToolDescriptor(
        name="seclists",
        version="2023.2",
        description="Wordlist collection used for content, parameter and credential discovery (reference only).",
        entrypoint="hunterx.tools.knowledge.adapters:SeclistsAdapter",
        targets=("knowledge",),
        capabilities=("wordlist", "wordlist-provider"),
        permissions=(),
        parameters={
            "path": {"type": "string", "description": "Local checkout path of the dataset."},
            "preview": {"type": "array", "description": "Bounded preview entries."},
            "entry_count": {"type": "integer", "description": "Total entry count."},
        },
    )


class FuzzdbAdapter(KnowledgeDatasetAdapter):
    """SDK adapter for the FuzzDB attack and response pattern dictionary."""

    dataset_name = "FuzzDB"
    dataset_category = "fuzz"

    descriptor = ToolDescriptor(
        name="fuzzdb",
        version="2023-01-01",
        description="Attack and response pattern dictionaries for fuzzing (reference only).",
        entrypoint="hunterx.tools.knowledge.adapters:FuzzdbAdapter",
        targets=("knowledge",),
        capabilities=("response-patterns", "payload-intelligence"),
        permissions=(),
        parameters={
            "path": {"type": "string", "description": "Local checkout path of the dataset."},
            "preview": {"type": "array", "description": "Bounded preview entries."},
            "entry_count": {"type": "integer", "description": "Total entry count."},
        },
    )


def _preview(value: Any, limit: int) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value][:limit]
    return []


def _entry_count(value: Any) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


__all__ = ["PayloadsAllTheThingsAdapter", "SeclistsAdapter", "FuzzdbAdapter"]
