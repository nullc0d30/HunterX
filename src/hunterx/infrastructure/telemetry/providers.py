# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Telemetry providers.

Providers aggregate metrics, tracing and export under one
:class:`~hunterx.domain.ports.observability.TelemetryProviderPort`:

- :class:`MemoryTelemetryProvider` — default, everything in-process.
- :class:`PrometheusTelemetryProvider` — Prometheus text exposition export.
- :class:`OpenTelemetryTelemetryProvider` — OTLP export when
  ``opentelemetry`` is installed (optional extra).
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.ports.observability import MetricsPort, TelemetryProviderPort, TracerPort
from hunterx.infrastructure.metrics import InMemoryMetrics
from hunterx.infrastructure.tracing import InMemoryTracer

ProviderKind = str


class MemoryTelemetryProvider(TelemetryProviderPort):
    """Default provider: in-memory metrics and tracing."""

    def __init__(
        self,
        *,
        metrics: MetricsPort | None = None,
        tracer: TracerPort | None = None,
    ) -> None:
        self._metrics = metrics or InMemoryMetrics()
        self._tracer = tracer or InMemoryTracer()

    def metrics(self) -> MetricsPort:
        """Return the metrics collector."""
        return self._metrics

    def tracer(self) -> TracerPort:
        """Return the tracer."""
        return self._tracer

    def export(self) -> str:
        """Return a Prometheus text exposition of current metrics."""
        if isinstance(self._metrics, InMemoryMetrics):
            return self._metrics.render_prometheus()
        return ""


class PrometheusTelemetryProvider(MemoryTelemetryProvider):
    """Provider that additionally renders Prometheus exposition format."""

    def export(self) -> str:
        """Return Prometheus text exposition of current metrics."""
        if isinstance(self._metrics, InMemoryMetrics):
            return self._metrics.render_prometheus()
        return ""


class OpenTelemetryTelemetryProvider(MemoryTelemetryProvider):
    """Provider exporting to OpenTelemetry when the optional extra is present.

    If ``opentelemetry-api`` / ``opentelemetry-sdk`` are not installed, the
    provider degrades to the in-memory backend and logs the absence once.
    """

    def __init__(
        self,
        *,
        metrics: MetricsPort | None = None,
        tracer: TracerPort | None = None,
        service_name: str = "hunterx",
    ) -> None:
        super().__init__(metrics=metrics, tracer=tracer)
        self._service_name = service_name
        self._otlp_available = False
        self._warned = False
        try:  # pragma: no cover - optional dependency
            from opentelemetry import trace  # type: ignore[import-not-found]
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore[import-not-found]
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
            from opentelemetry.sdk.trace.export import (  # type: ignore[import-not-found]
                BatchSpanProcessor,
            )
        except ImportError:
            self._otlp_available = False
        else:
            self._otlp_available = True
            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            trace.set_tracer_provider(provider)
            self._tracer = tracer or InMemoryTracer()

    def export(self) -> str:
        """Return an export summary (OTLP export is push-based)."""
        if not self._otlp_available and not self._warned:
            import logging

            logging.getLogger("hunterx.telemetry").warning(
                "opentelemetry extras not installed; using in-memory telemetry"
            )
            self._warned = True
        return super().export()


def build_provider(kind: str = "memory", **kwargs: Any) -> TelemetryProviderPort:
    """Build a telemetry provider by kind: ``memory``, ``prometheus``, ``otel``."""
    providers: dict[str, type[TelemetryProviderPort]] = {
        "memory": MemoryTelemetryProvider,
        "prometheus": PrometheusTelemetryProvider,
        "otel": OpenTelemetryTelemetryProvider,
        "opentelemetry": OpenTelemetryTelemetryProvider,
    }
    provider_cls = providers.get(kind.lower(), MemoryTelemetryProvider)
    return provider_cls(**kwargs)
