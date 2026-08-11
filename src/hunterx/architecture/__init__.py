# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""HunterX Architecture Enforcement Framework.

A static, dependency-light architecture linter that enforces the Clean
Architecture rules ratified in the HunterX Development Bible
(``docs/bible/02 - Architecture.md``, ``docs/bible/03 - Folder Structure.md``).

Responsibilities:

- Validate layer boundaries against the machine-readable dependency matrix.
- Detect circular dependencies, plugin/tool boundary escapes and forbidden
  imports with remediation guidance for every violation.
- Check documentation completeness and API stability against a baseline.

Dependencies:

- Only the Python standard library and ``pyyaml``; never the hunterx runtime,
  so the linter runs standalone in CI.

Extension points:

- The dependency policy is data-driven via ``config/architecture.yaml``;
  new layers, rules, waivers and known cycles are added there without code
  changes.

Run it with ``hunterx-arch`` or ``python -m hunterx.architecture``.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
