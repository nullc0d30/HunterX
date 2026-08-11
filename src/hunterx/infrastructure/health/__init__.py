# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Health monitoring adapters.

The :class:`HealthRegistry` runs a named set of component probes and reports a
unified status map. Probes are small callables returning ``(status, detail)``
where status is ``ok``, ``degraded`` or ``down``. The registry powers the
platform health API and the unified health dashboard.
"""

from __future__ import annotations

import threading
from typing import Any

from hunterx.domain.ports.observability import HealthProbePort, HealthRegistryPort

_OK = "ok"
_DEGRADED = "degraded"
_DOWN = "down"


class HealthProbe:
    """A callable-backed component probe."""

    def __init__(self, name: str, check: Any) -> None:
        self.name = name
        self._check = check

    def check(self) -> tuple[str, str]:
        """Run the probe and return ``(status, detail)``."""
        try:
            result = self._check()
            if isinstance(result, tuple):
                return result
            return (_OK, str(result))
        except Exception as exc:  # noqa: BLE001 - probes must never raise
            return (_DOWN, str(exc))


class HealthRegistry(HealthRegistryPort):
    """Registry of named component health probes."""

    def __init__(self) -> None:
        self._probes: dict[str, HealthProbe] = {}
        self._lock = threading.RLock()

    def register(self, probe: HealthProbePort) -> None:
        """Register a component probe (replaces same-name probes)."""
        with self._lock:
            self._probes[probe.name] = probe  # type: ignore[assignment]

    def register_callable(self, name: str, check: Any) -> None:
        """Register a probe backed by a plain callable."""
        self.register(HealthProbe(name, check))

    def unregister(self, name: str) -> None:
        """Remove a component probe by name."""
        with self._lock:
            self._probes.pop(name, None)

    def check_all(self) -> dict[str, dict[str, str]]:
        """Run every probe and return ``{component: {status, detail}}``."""
        with self._lock:
            probes = list(self._probes.values())
        results: dict[str, dict[str, str]] = {}
        for probe in probes:
            status, detail = probe.check()
            results[probe.name] = {"status": status, "detail": detail}
        return results

    def components(self) -> list[str]:
        """Return the names of all registered probes."""
        with self._lock:
            return sorted(self._probes)

    def summary(self) -> dict[str, Any]:
        """Return a dashboard-friendly health summary."""
        checks = self.check_all()
        statuses = [entry["status"] for entry in checks.values()]
        return {
            "components": checks,
            "ok": sum(1 for s in statuses if s == _OK),
            "degraded": sum(1 for s in statuses if s == _DEGRADED),
            "down": sum(1 for s in statuses if s == _DOWN),
            "total": len(statuses),
            "overall": _OK
            if all(s == _OK for s in statuses)
            else (_DEGRADED if not any(s == _DOWN for s in statuses) else _DOWN),
        }
