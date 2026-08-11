# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Code generators: adapter, error handling, logging and telemetry.

Emits the Python skeletons of a Tool Integration Pack — the SDK tool adapter,
typed errors, module logging and runtime telemetry — all rendered from
integration templates.
"""

from __future__ import annotations

from hunterx.domain.tool_factory import PackArtifactKind
from hunterx.tools.factory.generators.base import PackContext, PackGenerator
from hunterx.tools.factory.templates import BUILTIN_FILES


class AdapterGenerator(PackGenerator):
    """Generates the tool adapter skeleton (``adapters/adapter.py``)."""

    name = "adapter"
    description = "Generates the SDK tool adapter skeleton."

    def generate(self, ctx: PackContext):
        """Emit the SDK tool adapter skeleton."""
        content = self.render(ctx, "adapters/adapter.py", BUILTIN_FILES["adapters/adapter.py"])
        return [self.file("adapters/adapter.py", content, PackArtifactKind.ADAPTER)]


class ErrorHandlingGenerator(PackGenerator):
    """Generates typed pack errors (``runtime/errors.py``)."""

    name = "error-handling"
    description = "Generates the typed error classes for the pack."

    def generate(self, ctx: PackContext):
        """Emit the typed pack error classes."""
        content = self.render(ctx, "runtime/errors.py", BUILTIN_FILES["runtime/errors.py"])
        return [self.file("runtime/errors.py", content, PackArtifactKind.ERROR_HANDLING)]


class LoggingGenerator(PackGenerator):
    """Generates module logging (``runtime/logging.py``)."""

    name = "logging"
    description = "Generates the pack logger."

    def generate(self, ctx: PackContext):
        """Emit the pack logger module."""
        content = self.render(ctx, "runtime/logging.py", BUILTIN_FILES["runtime/logging.py"])
        return [self.file("runtime/logging.py", content, PackArtifactKind.LOGGING)]


class TelemetryGenerator(PackGenerator):
    """Generates runtime telemetry (``runtime/telemetry.py``)."""

    name = "telemetry"
    description = "Generates the runtime telemetry helper."

    def generate(self, ctx: PackContext):
        """Emit the runtime telemetry helper."""
        content = self.render(ctx, "runtime/telemetry.py", BUILTIN_FILES["runtime/telemetry.py"])
        return [self.file("runtime/telemetry.py", content, PackArtifactKind.TELEMETRY)]
