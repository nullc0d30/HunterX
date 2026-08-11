# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Logging adapters.

Structured JSON logging with:

- correlation/causation id injection from the tracing context,
- sensitive-data masking for configured keys,
- log enrichment (static and dynamic fields),
- rotating file handlers for long-running processes.

The :class:`LoggingManager` wires the root logger once and hands out child
loggers to every subsystem.
"""

from __future__ import annotations

import contextvars
import json
import logging
from collections.abc import Mapping
from logging.handlers import RotatingFileHandler as _RotatingFileHandler
from typing import Any

#: Thread-local correlation context (propagated into every log record).
_correlation: contextvars.ContextVar[dict[str, str | None] | None] = contextvars.ContextVar(
    "hunterx_correlation", default=None
)

#: Keys whose values are masked before emission.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "private_key",
    }
)


def set_correlation(**fields: str | None) -> None:
    """Set correlation fields (correlation_id, causation_id, mission_id, ...)."""
    current = dict(_correlation.get() or {})
    current.update({k: v for k, v in fields.items() if v is not None})
    _correlation.set(current)


def clear_correlation() -> None:
    """Clear the thread-local correlation context."""
    _correlation.set(None)


def get_correlation() -> dict[str, str | None]:
    """Return a copy of the current correlation context."""
    return dict(_correlation.get() or {})


def _mask(value: Any) -> Any:
    """Mask a string, leaving short values fully masked."""
    if isinstance(value, str) and value:
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}***{value[-2:]}"
    return value


def _deep_mask(payload: Any, sensitive: frozenset[str] = _SENSITIVE_KEYS) -> Any:
    """Recursively mask sensitive keys in nested mappings and lists."""
    if isinstance(payload, Mapping):
        return {
            key: (_mask(value) if str(key).lower() in sensitive else _deep_mask(value, sensitive))
            for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [_deep_mask(item, sensitive) for item in payload]
    return payload


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON for structured ingestion.

    Records carry: level, logger, message, module, line, the correlation
    context (when present), any ``fields`` attached to the record (with
    sensitive keys masked) and an exception trace when one is present.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a log record as a single-line JSON object."""
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        correlation = get_correlation()
        if correlation:
            payload["correlation"] = correlation
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(_deep_mask(fields))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class JsonRotatingFileHandler(_RotatingFileHandler):
    """Rotating file handler that writes the JSON-formatted records."""

    def __init__(
        self,
        filename: str,
        *,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
        encoding: str = "utf-8",
    ) -> None:
        super().__init__(
            filename, maxBytes=max_bytes, backupCount=backup_count, encoding=encoding
        )
        self.setFormatter(JsonFormatter())


class LoggingManager:
    """Central logging configuration.

    Configures the root logger once, applies a level, optionally switches to
    JSON output and configures rotation. Returns a child logger per subsystem.
    """

    _configured = False

    def __init__(
        self,
        *,
        level: str = "INFO",
        json_output: bool = False,
        log_file: str | None = None,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 5,
    ) -> None:
        self._level = level
        self._json_output = json_output
        self._log_file = log_file
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self.configure()

    def configure(self) -> None:
        """Apply the root-logger configuration (idempotent)."""
        if LoggingManager._configured and not self._json_output:
            return
        root = logging.getLogger()
        root.setLevel(self._level.upper())
        handlers: list[logging.Handler] = []
        formatter: logging.Formatter = (
            JsonFormatter() if self._json_output else logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s"
            )
        )
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        handlers.append(console)
        if self._log_file:
            if self._json_output:
                file_handler = JsonRotatingFileHandler(
                    self._log_file,
                    max_bytes=self._max_bytes,
                    backup_count=self._backup_count,
                )
            else:
                file_handler = _RotatingFileHandler(
                    self._log_file,
                    maxBytes=self._max_bytes,
                    backupCount=self._backup_count,
                )
                file_handler.setFormatter(formatter)
            handlers.append(file_handler)
        root.handlers = handlers
        LoggingManager._configured = True

    def get_logger(self, name: str) -> logging.Logger:
        """Return a child logger for ``name``."""
        return logging.getLogger(name)

    def set_level(self, level: str) -> None:
        """Change the root logging level at runtime."""
        logging.getLogger().setLevel(level.upper())
        self._level = level
