# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API application factory and error middleware."""

from __future__ import annotations

from typing import Any

from hunterx.config.settings import Settings


def create_app(
    settings: Settings | None = None,
    *,
    register_health: bool = True,
    platform: Any | None = None,
) -> Any:
    """Build and return a configured FastAPI application.

    Args:
        settings: optional typed settings; defaults are used when omitted.
        register_health: whether to add a ``/health`` route.
        platform: an optional already-composed platform. When omitted, one is
            built and its container is shared with the FastAPI dependency
            layer so handlers resolve the same services as the rest of the
            runtime.

    Returns:
        A configured FastAPI ``FastAPI`` instance.

    Raises:
        RuntimeError: if FastAPI is not installed (the ``api`` extra).

    """
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("FastAPI is required to build the API; install the 'api' extra.") from exc

    from hunterx.api.auth import ApiAuthConfig, configure_auth
    from hunterx.api.deps import configure_container
    from hunterx.api.middleware import register_exception_handlers
    from hunterx.api.router import ApiRouter

    if settings is None:
        from hunterx.config.loader import load_default_settings

        settings = load_default_settings()

    if platform is None:
        from hunterx.platform import build_platform

        platform = build_platform(settings)

    configure_container(platform.container)

    configure_auth(
        ApiAuthConfig(
            enabled=bool(settings.api.auth_enabled or settings.api.api_key),
            api_key=settings.api.api_key,
            read_only_key=settings.api.read_only_key,
        )
    )

    app = FastAPI(title=settings.app_name, version="7.0.0")
    register_exception_handlers(app)

    from hunterx.api.auth import auth_config

    if auth_config().enabled:
        from collections.abc import Awaitable, Callable

        from fastapi import Request
        from fastapi.responses import JSONResponse
        from starlette.responses import Response

        @app.middleware("http")
        async def _enforce_api_auth(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            config = auth_config()
            if config.exempt(request.url.path):
                return await call_next(request)
            role = config.role_for(request.headers.get("X-API-Key", ""))
            if role is None:
                return JSONResponse(
                    status_code=401,
                    content={"error": {"code": 401, "code_name": "UNAUTHENTICATED", "message": "a valid X-API-Key header is required"}},
                )
            if not config.may(role, request.method):
                return JSONResponse(
                    status_code=403,
                    content={"error": {"code": 403, "code_name": "FORBIDDEN", "message": "this key has read-only access"}},
                )
            return await call_next(request)

    if register_health:
        router = ApiRouter()

        @router.get("/health", summary="Liveness probe")
        def health() -> dict[str, str]:
            return {"status": "ok"}

        router.apply_to(app)

    from hunterx.api.adaptive_mission_planning import build_adaptive_mission_planning_router
    from hunterx.api.finding import build_finding_router
    from hunterx.api.mission_dashboard import build_mission_dashboard_router
    from hunterx.api.mission_orchestration import build_mission_orchestration_router
    from hunterx.api.reporting import build_reporting_router
    from hunterx.api.target_memory import build_target_memory_router
    from hunterx.api.tools import build_tools_router

    build_adaptive_mission_planning_router().apply_to(app)
    build_mission_orchestration_router().apply_to(app)
    build_mission_dashboard_router().apply_to(app)
    build_finding_router().apply_to(app)
    build_reporting_router().apply_to(app)
    build_target_memory_router().apply_to(app)
    build_tools_router().apply_to(app)

    return app
