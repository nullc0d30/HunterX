# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared session-header helpers for binary tool adapters.

Converts the execution-context session surface (``cookies`` / ``headers``
parameters injected by the mission runner when an authenticated session is
established) into the ``-H`` style arguments the external tools consume. When
no session is configured the helper contributes nothing, so anonymous
executions are byte-for-byte unchanged.
"""

from __future__ import annotations

from typing import Any


def header_args(context: Any, *, flag: str = "-H") -> list[str]:
    """Return ``[flag, "Name: value", ...]`` for the context's session headers.

    Reads ``context.parameters["cookies"]`` (a mapping of cookie name to
    value) and ``context.parameters["headers"]`` (a mapping of extra request
    headers). Returns an empty list when neither is configured.
    """
    argv: list[str] = []
    cookies = _mapping(context, "cookies")
    if cookies:
        cookie_value = "; ".join(f"{name}={value}" for name, value in cookies.items())
        argv.extend([flag, f"Cookie: {cookie_value}"])
    headers = _mapping(context, "headers")
    for name, value in headers.items():
        argv.extend([flag, f"{name}: {value}"])
    return argv


def _mapping(context: Any, key: str) -> dict[str, str]:
    parameters = getattr(context, "parameters", None)
    if not isinstance(parameters, dict):
        return {}
    value = parameters.get(key)
    if isinstance(value, dict):
        return {str(name): str(item) for name, item in value.items()}
    return {}


__all__ = ["header_args"]
