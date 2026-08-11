# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe validation tool adapters.

Deterministic, in-process safe-probe adapters used by the validation engine.
They only ever emit canonical observations derived from bounded inputs — they
never fetch, execute or modify anything outside the parameters they receive,
and every probe is expected to be a read-only/passive/benign-marker check that
already passed the scope and safety gates.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.vulnerability_validation.enums import EvidenceKind
from hunterx.domain.vulnerability_validation.models import ValidationObservation
from hunterx.tools.safe_validation.base import ValidationToolAdapter, _observation


class PassiveProbeAdapter(ValidationToolAdapter):
    """Emit observations provided in the parameters (test/controlled path).

    The ``observations`` parameter carries a list of ``{"kind", "value",
    "confidence", "metadata"}`` entries that a caller (the validation engine or
    a test harness) has already normalized. The adapter re-emits them as
    canonical observations without alteration — raw tool output is never
    treated as a verdict by the engine.
    """

    descriptor = ToolDescriptor(
        name="passive-probe",
        version="1.0.0",
        description="Passive in-process safe probe emitting canonical observations.",
        entrypoint="hunterx.tools.safe_validation.adapters:PassiveProbeAdapter",
        targets=("url", "host", "domain", "ip", "service"),
        capabilities=("safe-validation", "passive-probe"),
        parameters={
            "observations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "value": {"type": "string"},
                        "confidence": {"type": "number"},
                    },
                },
            },
            "target": {"type": "string"},
        },
        permissions=("none",),
    )

    def probe(
        self,
        context: ExecutionContext,
        *,
        target: str,
        parameters: dict[str, Any],
    ) -> list[ValidationObservation]:
        """Emit canonical observations from the ``observations`` parameter."""
        observations: list[ValidationObservation] = []
        for entry in parameters.get("observations") or ():
            if not isinstance(entry, dict):
                continue
            value = entry.get("value")
            if value is None:
                continue
            try:
                kind = EvidenceKind(str(entry.get("kind") or "external").lower())
            except ValueError:
                kind = EvidenceKind.EXTERNAL
            try:
                confidence = float(entry.get("confidence") or 1.0)
            except (TypeError, ValueError):
                confidence = 1.0
            observations.append(
                _observation(
                    kind,
                    str(value),
                    confidence=confidence,
                    source=context.tool_id,
                    metadata=dict(entry.get("metadata") or {}),
                )
            )
        return observations


class VersionProbeAdapter(ValidationToolAdapter):
    """Emit a version observation for version-based validation.

    The ``version`` parameter carries the observed version and ``version_fixed``
    indicates whether a fixed version was already observed. Used by
    ``VERSION_VALIDATION`` strategies to build evidence for
    known-vulnerable-software hypotheses.
    """

    descriptor = ToolDescriptor(
        name="version-probe",
        version="1.0.0",
        description="Version observation probe for safe version-based validation.",
        entrypoint="hunterx.tools.safe_validation.adapters:VersionProbeAdapter",
        targets=("url", "host", "domain", "ip", "service"),
        capabilities=("safe-validation", "version-validation", "version-probe"),
        parameters={
            "version": {"type": "string"},
            "version_fixed": {"type": "boolean"},
            "target": {"type": "string"},
        },
        permissions=("none",),
    )

    def probe(
        self,
        context: ExecutionContext,
        *,
        target: str,
        parameters: dict[str, Any],
    ) -> list[ValidationObservation]:
        """Emit a version observation (or none when no version is provided)."""
        version = str(parameters.get("version") or "")
        if not version:
            return []
        fixed = bool(parameters.get("version_fixed"))
        return [
            _observation(
                EvidenceKind.VERSION,
                version,
                confidence=1.0 if not fixed else 0.0,
                source=context.tool_id,
                metadata={"target": target, "fixed": fixed},
            )
        ]


class ErrorBehaviorProbeAdapter(ValidationToolAdapter):
    """Emit an error-behavior observation for safe error-behavior validation.

    The ``error_signal`` parameter indicates whether the benign probe surfaced
    an error-behavior signal; ``error_message`` carries the (redacted) message.
    """

    descriptor = ToolDescriptor(
        name="error-behavior-probe",
        version="1.0.0",
        description="Error-behavior observation probe for safe validation.",
        entrypoint="hunterx.tools.safe_validation.adapters:ErrorBehaviorProbeAdapter",
        targets=("url", "host", "domain", "ip", "service"),
        capabilities=("safe-validation", "error-behavior-validation", "error-behavior-probe"),
        parameters={
            "error_signal": {"type": "boolean"},
            "error_message": {"type": "string"},
            "target": {"type": "string"},
        },
        permissions=("none",),
    )

    def probe(
        self,
        context: ExecutionContext,
        *,
        target: str,
        parameters: dict[str, Any],
    ) -> list[ValidationObservation]:
        """Emit an error-behavior observation when an error signal is present."""
        if not bool(parameters.get("error_signal")):
            return []
        message = str(parameters.get("error_message") or "")
        return [
            _observation(
                EvidenceKind.ERROR_MESSAGE,
                message or "error-behavior signal observed",
                confidence=1.0,
                source=context.tool_id,
                metadata={"target": target},
            )
        ]


def validation_adapters() -> dict[str, ValidationToolAdapter]:
    """Return a fresh mapping of validation tool id to adapter instance."""
    return {
        "passive-probe": PassiveProbeAdapter(),
        "version-probe": VersionProbeAdapter(),
        "error-behavior-probe": ErrorBehaviorProbeAdapter(),
    }


__all__ = [
    "ErrorBehaviorProbeAdapter",
    "PassiveProbeAdapter",
    "ValidationToolAdapter",
    "VersionProbeAdapter",
    "validation_adapters",
]
