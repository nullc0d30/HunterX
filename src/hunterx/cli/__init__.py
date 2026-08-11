# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""CLI framework.

A small, dependency-free command framework. Commands are registered by name
and dispatched from ``hunterx.cli:main``. Output rendering is pluggable
(text, json, yaml, csv).
"""

from __future__ import annotations

from hunterx.cli.app import CliApplication, main
from hunterx.cli.registry import CommandRegistry
from hunterx.cli.render import OutputRenderer

__all__ = ["CliApplication", "main", "CommandRegistry", "OutputRenderer"]
