# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base exception and error codes."""

from __future__ import annotations

from enum import IntEnum


class HunterXErrorCode(IntEnum):
    """Machine-readable error codes shared across layers."""

    UNKNOWN = 0
    CONFIGURATION = 1000
    VALIDATION = 1100
    DOMAIN = 1200
    PERSISTENCE = 2000
    CACHE = 2100
    QUEUE = 2200
    CONNECTION = 2300
    SECRET = 2400
    SANDBOX = 2500
    OPERATION = 3000
    MISSION = 3100
    PLUGIN = 3200
    TOOL = 3300
    FACTORY = 3350
    SCHEDULER = 3400
    REPORTING = 3500
    AUTHENTICATION = 3600
    AUTHORIZATION = 3700


class HunterXError(Exception):
    """Base class for every error raised by HunterX.

    Attributes:
        code: machine-readable :class:`HunterXErrorCode`.

    """

    code: HunterXErrorCode = HunterXErrorCode.UNKNOWN

    def __init__(self, message: str, *, code: HunterXErrorCode | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, str | int]:
        """Serialize the error to a JSON-safe mapping."""
        return {"code": int(self.code), "code_name": self.code.name, "message": self.message}
