# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool registry."""

from __future__ import annotations

from threading import RLock

from hunterx.domain.exceptions import DuplicateRegistrationError
from hunterx.domain.ports.services import ToolRegistryPort
from hunterx.domain.tools import ToolDescriptor


class ToolRegistry(ToolRegistryPort):
    """Thread-safe registry of tool descriptors."""

    def __init__(self) -> None:
        self._descriptors: dict[str, ToolDescriptor] = {}
        self._lock = RLock()

    def register(self, descriptor: ToolDescriptor) -> None:
        """Register a tool descriptor by name."""
        with self._lock:
            if descriptor.name in self._descriptors:
                raise DuplicateRegistrationError(descriptor.name)
            self._descriptors[descriptor.name] = descriptor

    def unregister(self, name: str) -> None:
        """Remove a tool descriptor by name."""
        with self._lock:
            self._descriptors.pop(name, None)

    def get(self, name: str) -> ToolDescriptor | None:
        """Return a descriptor by name or ``None``."""
        with self._lock:
            return self._descriptors.get(name)

    def list(self) -> list[ToolDescriptor]:
        """Return all registered descriptors."""
        with self._lock:
            return list(self._descriptors.values())
