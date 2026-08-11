# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Dependency-injection container.

A minimal, explicit service container. Implementations are registered as
types or factories and resolved lazily. Components depend on abstract ports
(defined in ``hunterx.domain.ports``) and receive their concrete adapters
through this container at composition time.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, Generic, TypeVar, cast

from hunterx.domain.exceptions import DuplicateRegistrationError, RegistrationNotFoundError

T = TypeVar("T")

_Factory = Callable[["Container[Any]"], T]


class Container(Generic[T]):
    """Thread-safe service container.

    The container is intentionally generic over the service type so a project
    can hold many well-typed containers (e.g. one per application domain).
    """

    def __init__(self, parent: Container[Any] | None = None) -> None:
        self._parent = parent
        self._factories: dict[type[Any], _Factory[Any]] = {}
        self._instances: dict[type[Any], Any] = {}
        self._singletons: set[type[Any]] = set()
        self._lock = threading.RLock()

    def register(self, key: type[T], factory: _Factory[T], *, singleton: bool = False) -> None:
        """Register ``factory`` for ``key``.

        Raises:
            DuplicateRegistrationError: if ``key`` is already registered locally.

        """
        with self._lock:
            if key in self._factories:
                raise DuplicateRegistrationError(key)
            self._factories[key] = factory
            if singleton:
                self._singletons.add(key)

    def register_instance(self, key: type[T], instance: T) -> None:
        """Register an already-constructed instance for ``key``."""
        with self._lock:
            if key in self._factories:
                raise DuplicateRegistrationError(key)
            self._factories[key] = lambda _container: instance
            self._instances[key] = instance

    def resolve(self, key: type[T]) -> T:
        """Resolve the service registered for ``key``.

        Raises:
            RegistrationNotFoundError: if no factory is registered anywhere in
                the container chain.

        """
        with self._lock:
            factory = cast(_Factory[T] | None, self._factories.get(key))
            if factory is not None:
                if key in self._instances:
                    return cast(T, self._instances[key])
                if key in self._singletons:
                    instance = factory(self)
                    self._instances[key] = instance
                    return instance
                return factory(self)
        if self._parent is not None:
            return cast(T, self._parent.resolve(key))
        raise RegistrationNotFoundError(key)

    def has(self, key: type[T]) -> bool:
        """Return ``True`` if ``key`` is resolvable in this container chain."""
        if key in self._factories:
            return True
        if self._parent is not None:
            return self._parent.has(key)
        return False
