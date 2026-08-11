# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Telemetry adapters.

Collects metrics, traces and logs through the
:class:`~hunterx.domain.ports.services.TelemetryPort` contract. The default
adapter keeps everything in memory and hands values to a sink function; export
adapters (Prometheus, OTLP) arrive in future sprints.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from hunterx.domain.ports.services import TelemetryPort

_Sink = Callable[[str, float, dict[str, str] | None], None]


class MemoryTelemetry(TelemetryPort):
    """In-memory telemetry sink.

    Metric values are stored as (value, timestamp) pairs per name; a callback
    sink can additionally receive every recorded metric.
    """

    def __init__(self, *, sink: _Sink | None = None) -> None:
        self._sink = sink
        self._metrics: dict[str, list[tuple[float, float]]] = defaultdict(list)
        self._lock = threading.RLock()

    def record_metric(self, name: str, value: float, *, tags: dict[str, str] | None = None) -> None:
        """Record a numeric metric under ``name``, passing it to any sink."""
        with self._lock:
            self._metrics[name].append((value, time.monotonic()))
        if self._sink is not None:
            self._sink(name, value, tags)

    def log(self, level: str, message: str, *, fields: dict[str, Any] | None = None) -> None:
        """Emit a structured log entry at ``level``."""
        logging.getLogger("hunterx.telemetry").log(
            getattr(logging, level.upper(), logging.INFO), message, extra={"fields": fields or {}}
        )

    def snapshot(self) -> dict[str, list[tuple[float, float]]]:
        """Return a copy of the recorded metrics."""
        with self._lock:
            return {name: list(values) for name, values in self._metrics.items()}
