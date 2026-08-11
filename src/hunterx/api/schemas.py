# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base API schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class APIModel(BaseModel):
    """Base class for all request/response schemas.

    Extra fields are ignored so forward/backward compatible API evolution is
    possible without breaking existing clients.
    """

    model_config = ConfigDict(extra="ignore")


class ErrorResponse(APIModel):
    """Standard error response body."""

    code: int
    code_name: str
    message: str
    details: list[Any] = []
