# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Platform composition root.

The composition root of HunterX v7: assembles every facade, engine, service
and adapter into a single :class:`~hunterx.platform.platform.Platform` and
wires them in a dependency container. Applications (API, CLI, daemons) build
or receive a :class:`Platform` and resolve their services from it.
"""

from __future__ import annotations

from hunterx.platform.assembler import build_platform
from hunterx.platform.platform import Platform

__all__ = [
    "Platform",
    "build_platform",
]
