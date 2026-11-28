# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX v7, AI-Powered Security Orchestration & Intelligence Platform

"""HunterX v7 core package.

This package is the Clean Architecture backbone of the HunterX platform.
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
