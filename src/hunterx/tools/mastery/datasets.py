# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Dataset registry.

SecLists, FuzzDB, PayloadsAllTheThings, Nuclei templates, Semgrep rules,
Gitleaks rules, Trivy DB, ExploitDB... These are datasets, not mere files.
Each is versioned, sourced, licensed and safety-classified. Updates are
versioned, validated, auditable and rollback-capable.
"""

from __future__ import annotations

import threading

from hunterx.domain.tool_mastery import ToolDataset


class ToolDatasetRegistry:
    """Registry of versioned security datasets with provenance."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._datasets: dict[str, ToolDataset] = {}
        self._versions: dict[str, list[ToolDataset]] = {}

    def register(self, dataset: ToolDataset) -> None:
        """Register (or replace) a dataset and archive its version history."""
        with self._lock:
            previous = self._datasets.get(dataset.dataset_id)
            if previous is not None and previous.version != dataset.version:
                self._versions.setdefault(dataset.dataset_id, []).insert(0, previous)
            self._datasets[dataset.dataset_id] = dataset

    def register_all(self, datasets: list[ToolDataset]) -> None:
        """Register several datasets at once."""
        for dataset in datasets:
            self.register(dataset)

    def get(self, dataset_id: str) -> ToolDataset | None:
        """Return the current dataset by id."""
        with self._lock:
            return self._datasets.get(dataset_id)

    def list(self) -> tuple[ToolDataset, ...]:
        """Return every current dataset."""
        with self._lock:
            return tuple(sorted(self._datasets.values(), key=lambda d: d.dataset_id))

    def by_category(self, category: str) -> tuple[ToolDataset, ...]:
        """Return datasets in a category."""
        with self._lock:
            return tuple(
                dataset for dataset in self._datasets.values() if dataset.category == category
            )

    def versions(self, dataset_id: str) -> tuple[ToolDataset, ...]:
        """Return the archived version history (newest first, excluding current)."""
        with self._lock:
            return tuple(self._versions.get(dataset_id, []))

    def rollback(self, dataset_id: str) -> ToolDataset | None:
        """Roll back to the previous version; returns the restored dataset.

        Returns:
            The restored previous dataset, or ``None`` when there is no
            archived version to restore.

        """
        with self._lock:
            archived = self._versions.get(dataset_id, [])
            if not archived:
                return None
            previous = archived.pop(0)
            current = self._datasets.get(dataset_id)
            if current is not None:
                self._versions.setdefault(dataset_id, []).insert(0, current)
            self._datasets[dataset_id] = previous
            return previous

    def checksum(self, dataset_id: str) -> str:
        """Return the current checksum of a dataset (or ``""``)."""
        dataset = self.get(dataset_id)
        return dataset.checksum if dataset is not None else ""
