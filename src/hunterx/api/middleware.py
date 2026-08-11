# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API error middleware.

Maps :class:`~hunterx.domain.exceptions.HunterXError` and generic exceptions
to structured :class:`~hunterx.api.schemas.ErrorResponse` bodies.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.exceptions import AuthorizationError, HunterXError, NotFoundError
from hunterx.domain.exceptions.config import ConfigurationError
from hunterx.domain.exceptions.infrastructure import InfrastructureError
from hunterx.domain.exceptions.operation import OperationError

_STATUS_MAP: list[tuple[type[Exception], int]] = [
    (NotFoundError, 404),
    (AuthorizationError, 403),
    (ConfigurationError, 500),
    (InfrastructureError, 503),
    (OperationError, 400),
    (HunterXError, 500),
]


def _status_for(error: Exception) -> int:
    for error_type, status in _STATUS_MAP:
        if isinstance(error, error_type):
            return status
    return 500


def register_exception_handlers(app: Any) -> None:
    """Register domain and generic exception handlers on a FastAPI app."""

    @app.exception_handler(HunterXError)
    async def _hunterx_error_handler(request: Any, exc: HunterXError) -> Any:
        from fastapi.responses import JSONResponse

        payload = exc.to_dict()
        return JSONResponse(status_code=_status_for(exc), content={"error": payload})

    @app.exception_handler(Exception)
    async def _generic_error_handler(request: Any, exc: Exception) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": 0,
                    "code_name": "UNKNOWN",
                    "message": "An unexpected error occurred.",
                }
            },
        )
