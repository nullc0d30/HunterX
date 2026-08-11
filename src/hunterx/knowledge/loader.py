# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Knowledge loader.

Loads knowledge records from bundled or external JSON/YAML catalogs into the
registry. A catalog is a list of records with the fields defined by
:class:`~hunterx.knowledge.registry.KnowledgeRecord`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from hunterx.domain.exceptions import ConfigurationError
from hunterx.knowledge.registry import KnowledgeRecord, KnowledgeRegistry


class KnowledgeLoader:
    """Load knowledge catalogs into a :class:`KnowledgeRegistry`."""

    def load_file(self, registry: KnowledgeRegistry, path: str | Path) -> int:
        """Load all records from ``path`` (JSON or YAML). Return count added."""
        path = Path(path)
        suffix = path.suffix.lower()
        if suffix in (".json",):
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        elif suffix in (".yaml", ".yml"):
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
        else:
            raise ConfigurationError(f"Unsupported knowledge catalog format '{suffix}'.")
        records = data.get("records", data) if isinstance(data, dict) else data
        if not isinstance(records, list):
            raise ConfigurationError("Knowledge catalog must contain a list of records.")
        count = 0
        for raw in records:
            if not isinstance(raw, dict):
                continue
            registry.upsert(_record_from_mapping(raw))
            count += 1
        return count


def _record_from_mapping(raw: dict[str, Any]) -> KnowledgeRecord:
    return KnowledgeRecord(
        record_id=str(raw["record_id"]),
        title=str(raw.get("title", "")),
        category=str(raw.get("category", "general")),
        description=str(raw.get("description", "")),
        references=tuple(str(ref) for ref in raw.get("references", ())),
        tags=tuple(str(tag) for tag in raw.get("tags", ())),
        properties=dict(raw.get("properties", {})),
    )
