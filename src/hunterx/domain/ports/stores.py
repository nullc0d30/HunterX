# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Object-store, evidence and knowledge-graph ports."""

from __future__ import annotations

import abc
from typing import Any


class ObjectStorePort(abc.ABC):
    """Binary/object storage contract (filesystem, S3, MinIO, ...)."""

    @abc.abstractmethod
    def put(self, key: str, content: bytes, *, mime_type: str | None = None) -> None:
        """Store ``content`` under ``key``, overwriting any existing object."""

    @abc.abstractmethod
    def get(self, key: str) -> bytes:
        """Return the bytes stored under ``key``, raising when absent."""

    @abc.abstractmethod
    def exists(self, key: str) -> bool:
        """Return ``True`` when an object exists under ``key``."""

    @abc.abstractmethod
    def delete(self, key: str) -> None:
        """Delete the object under ``key``."""

    @abc.abstractmethod
    def list(self, prefix: str, *, limit: int = 100) -> list[str]:
        """Return object keys matching ``prefix``, up to ``limit`` entries."""


class EvidenceStore(ObjectStorePort, abc.ABC):
    """Object store specialized for immutable evidence artifacts."""

    @abc.abstractmethod
    def put(self, key: str, content: bytes, *, mime_type: str | None = None) -> None:
        """Store ``content`` under ``key``, overwriting any existing object."""

    @abc.abstractmethod
    def get(self, key: str) -> bytes:
        """Return the bytes stored under ``key``, raising when absent."""

    @abc.abstractmethod
    def exists(self, key: str) -> bool:
        """Return ``True`` when an object exists under ``key``."""

    @abc.abstractmethod
    def delete(self, key: str) -> None:
        """Delete the object under ``key``."""

    @abc.abstractmethod
    def list(self, prefix: str, *, limit: int = 100) -> list[str]:
        """Return object keys matching ``prefix``, up to ``limit`` entries."""


class KnowledgeGraphPort(abc.ABC):
    """Graph storage contract for knowledge records and relationships."""

    @abc.abstractmethod
    def upsert_node(self, node_id: str, *, labels: list[str], properties: dict[str, Any]) -> None:
        """Create or update a graph node with labels and properties."""

    @abc.abstractmethod
    def upsert_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        *,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Create or update a typed edge between two nodes."""

    @abc.abstractmethod
    def query_neighbors(self, node_id: str, *, depth: int = 1, limit: int = 100) -> list[dict[str, Any]]:
        """Return neighbor nodes reachable from ``node_id`` within ``depth`` hops."""

    @abc.abstractmethod
    def delete_node(self, node_id: str) -> None:
        """Delete the node and all edges incident to it."""
