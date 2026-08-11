# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Object-store adapters.

Provides a filesystem implementation of :class:`~hunterx.domain.ports.ObjectStorePort`
and :class:`~hunterx.domain.ports.EvidenceStore`. S3/MinIO adapters implement
the same ports.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.domain.exceptions import NotFoundError, PersistenceError
from hunterx.domain.ports.stores import EvidenceStore, ObjectStorePort


class FileSystemObjectStore(ObjectStorePort):
    """A directory-backed object store.

    Keys map to nested files under the configured root directory. The store
    creates missing parent directories on write.
    """

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        # Prevent path traversal by resolving within the root.
        path = (self._root / key).resolve()
        if not path.is_relative_to(self._root.resolve()):
            raise PersistenceError(f"Object key '{key}' escapes the store root.")
        return path

    def put(self, key: str, content: bytes, *, mime_type: str | None = None) -> None:
        """Store ``content`` under ``key``, creating parent directories."""
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def get(self, key: str) -> bytes:
        """Return the bytes stored under ``key``, raising when absent."""
        path = self._resolve(key)
        if not path.exists():
            raise NotFoundError("Object", key)
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        """Return ``True`` when an object exists under ``key``."""
        return self._resolve(key).exists()

    def delete(self, key: str) -> None:
        """Delete the object under ``key``, raising when absent."""
        path = self._resolve(key)
        if not path.exists():
            raise NotFoundError("Object", key)
        path.unlink()

    def list(self, prefix: str, *, limit: int = 100) -> list[str]:
        """Return object keys matching ``prefix``, up to ``limit`` entries."""
        base = self._resolve(prefix) if prefix else self._root
        results: list[str] = []
        for path in sorted(base.rglob("*")):
            if path.is_file():
                results.append(path.relative_to(self._root).as_posix())
                if len(results) >= limit:
                    break
        return results


class FileSystemEvidenceStore(EvidenceStore):
    """Object store specialized for immutable evidence artifacts.

    Backed by the same filesystem machinery as
    :class:`FileSystemObjectStore`; adds a versioning-friendly key namespace.
    """

    def __init__(self, root: str | Path) -> None:
        self._store = FileSystemObjectStore(root)

    def put(self, key: str, content: bytes, *, mime_type: str | None = None) -> None:
        """Store ``content`` under ``key``, overwriting any existing object."""
        self._store.put(key, content, mime_type=mime_type)

    def get(self, key: str) -> bytes:
        """Return the bytes stored under ``key``, raising when absent."""
        return self._store.get(key)

    def exists(self, key: str) -> bool:
        """Return ``True`` when an object exists under ``key``."""
        return self._store.exists(key)

    def delete(self, key: str) -> None:
        """Delete the object under ``key``."""
        self._store.delete(key)

    def list(self, prefix: str, *, limit: int = 100) -> list[str]:
        """Return object keys matching ``prefix``, up to ``limit`` entries."""
        return self._store.list(prefix, limit=limit)
