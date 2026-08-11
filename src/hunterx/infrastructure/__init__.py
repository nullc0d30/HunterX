# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Infrastructure adapters.

Implements the ports defined in :mod:`hunterx.domain.ports`. Adapters are the
only layer allowed to touch third-party libraries (SQLAlchemy, Redis clients,
Vault, etc.) and the OS. Each adapter is framework-optional: importing this
package never imports heavy dependencies eagerly.
"""

from __future__ import annotations

__all__ = ["db", "cache", "queue", "event_bus", "secrets", "sandbox", "ai", "logging", "telemetry"]
