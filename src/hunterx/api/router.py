# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API router registry.

Routes are declared as :class:`RouteSpec` data instead of being bound to a
web framework, so the same route table can drive FastAPI today and another
framework later.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_Handler = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class RouteSpec:
    """A declarative API route.

    Attributes:
        method: HTTP method (``GET``, ``POST``, ...).
        path: URL path with ``{placeholders}``.
        handler: the callable serving the route.
        summary: one-line description for OpenAPI docs.
        tags: OpenAPI tag groups.

    """

    method: str
    path: str
    handler: _Handler
    summary: str = ""
    tags: tuple[str, ...] = ()


class ApiRouter:
    """Collect route specifications and mount them on an app.

    ``apply_to`` adapts :class:`RouteSpec` entries to the target web framework
    (FastAPI is supported out of the box).
    """

    def __init__(self, prefix: str = "") -> None:
        self._prefix = prefix
        self._routes: list[RouteSpec] = []

    def add(self, method: str, path: str, handler: _Handler, *, summary: str = "", tags: tuple[str, ...] = ()) -> None:
        """Register a route."""
        self._routes.append(
            RouteSpec(method=method.upper(), path=path, handler=handler, summary=summary, tags=tags)
        )

    def get(self, path: str, *, summary: str = "", tags: tuple[str, ...] = ()) -> Callable[[_Handler], _Handler]:
        """Register a ``GET`` route and return its decorator."""
        return self._decorator("GET", path, summary, tags)

    def post(self, path: str, *, summary: str = "", tags: tuple[str, ...] = ()) -> Callable[[_Handler], _Handler]:
        """Register a ``POST`` route and return its decorator."""
        return self._decorator("POST", path, summary, tags)

    def _decorator(self, method: str, path: str, summary: str, tags: tuple[str, ...]) -> Callable[[_Handler], _Handler]:
        def wrapper(handler: _Handler) -> _Handler:
            self.add(method, path, handler, summary=summary, tags=tags)
            return handler

        return wrapper

    def routes(self) -> list[RouteSpec]:
        """Return all registered routes."""
        return list(self._routes)

    def apply_to(self, app: Any) -> None:
        """Mount all routes on a FastAPI app (``app.router`` or ``app``)."""
        import importlib.util

        if importlib.util.find_spec("fastapi") is None:  # pragma: no cover - optional dependency
            raise RuntimeError("FastAPI is required to apply routes; install the 'api' extra.")

        target = getattr(app, "router", app)
        for route in self.routes():
            method = getattr(target, route.method.lower())
            method(
                self._prefix + route.path,
                summary=route.summary,
                tags=list(route.tags) or None,
            )(route.handler)
