# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance-suite hooks.

The ``benchmark`` fixture comes from pytest-benchmark, which is an optional
development dependency. When it is not installed the benchmark tests are
skipped instead of erroring at setup; the plain timing tests still run.
"""

from __future__ import annotations

from typing import Any

import pytest

try:  # pragma: no cover - depends on the local environment
    import pytest_benchmark  # noqa: F401

    _HAS_BENCHMARK = True
except ImportError:  # pragma: no cover - depends on the local environment
    _HAS_BENCHMARK = False


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    """Skip tests that need the ``benchmark`` fixture when it is unavailable."""
    if _HAS_BENCHMARK:
        return
    skip = pytest.mark.skip(reason="pytest-benchmark is not installed")
    for item in items:
        if "benchmark" in getattr(item, "fixturenames", ()):
            item.add_marker(skip)
