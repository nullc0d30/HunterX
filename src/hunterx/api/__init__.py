# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""REST API framework.

Provides a FastAPI application factory, a router registry for endpoint
definition, base schemas and dependency helpers. Importing ``hunterx.api``
never requires FastAPI; it is only needed to build the app.
"""

from __future__ import annotations

from hunterx.api.router import ApiRouter, RouteSpec
from hunterx.api.schemas import ErrorResponse

__all__ = ["ApiRouter", "RouteSpec", "ErrorResponse"]
