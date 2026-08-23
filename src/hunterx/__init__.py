# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX v7 — AI-Powered Security Orchestration & Intelligence Platform

"""HunterX v7 core package.

This package is the Clean Architecture backbone of the HunterX platform. It
contains only foundation code: domain model, application services, engines,
infrastructure adapters, and the public SDKs. No scanners, no tool
implementations, no AI models, and no business logic live here.

Package layout follows the ratified Development Bible
(``docs/bible/03 - Folder Structure.md``):

- :mod:`hunterx.domain`         — pure domain layer (entities, ports, services)
- :mod:`hunterx.application`    — use-case layer
- :mod:`hunterx.infrastructure` — adapters (db, cache, queue, ai, sandbox, ...)
- :mod:`hunterx.engines`        — engine facades (mission, workflow, planner, ...)
- :mod:`hunterx.agents`         — multi-agent platform
- :mod:`hunterx.plugins`        — plugin system + public plugin SDK
- :mod:`hunterx.tools`          — tool adapter SDK + parser/normalizer framework
- :mod:`hunterx.knowledge`      — knowledge engine + knowledge graph
- :mod:`hunterx.scheduler`      — scheduler + jobs
- :mod:`hunterx.reporting`      — reporting infrastructure
- :mod:`hunterx.config`         — configuration manager
- :mod:`hunterx.shared`         — cross-cutting helpers (ids, masking, di, result)
- :mod:`hunterx.api`            — REST API framework (routing structure)
- :mod:`hunterx.cli`            — CLI framework (command structure)
"""

from __future__ import annotations

__version__ = "7.1.4"
__author__ = "Ahmed Awad (NullC0d3)"
__license__ = "Apache-2.0"

# NOTE: deliberately NOT importing any submodules here to keep the package
# import cheap and side-effect free. Subsystems are imported on demand.

__all__ = [
    "__version__",
    "__author__",
    "__license__",
]
