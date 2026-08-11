# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API dependency helpers.

Bridges the application layer and the web framework through the dependency
container, so handlers receive services without constructing them directly.
"""

from __future__ import annotations

from typing import Any, TypeVar

from hunterx.shared.di import Container

T = TypeVar("T")


class AppContainer:
    """A thin holder linking the shared container to API request scope.

    Handlers call :meth:`resolve` to obtain application services. In a
    production deployment the same container is populated at composition time.
    """

    def __init__(self, container: Container[Any] | None = None) -> None:
        self._container = container or Container()

    @property
    def container(self) -> Container[Any]:
        """Return the underlying service container."""
        return self._container

    def resolve(self, key: type[T]) -> T:
        """Resolve a service from the container."""
        return self._container.resolve(key)


def configure_container(container: Container[Any]) -> None:
    """Point the shared :class:`AppContainer` at a composed container.

    Called by the platform composition root at startup so FastAPI handlers
    resolve services through the same wiring used by the rest of the platform.
    """
    _CONTAINER._container = container


def get_container() -> AppContainer:
    """FastAPI dependency returning the shared :class:`AppContainer` singleton."""
    from hunterx.api.deps import _CONTAINER

    return _CONTAINER


_CONTAINER = AppContainer()
