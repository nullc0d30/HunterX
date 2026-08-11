# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Powered Security Orchestration & Intelligence Platform
# Backward-compatible entry point — delegates to the v7 package in src/.
#
# NOTE: the retired v6 flat package (hunterx/) is preserved in-tree for
# reference only. Its CLI must not be reached through this shim, so the v7
# src/ tree is placed on sys.path ahead of the repository root.

import sys
import os
import warnings

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC in sys.path:
    sys.path.remove(_SRC)
sys.path.insert(0, _SRC)

from hunterx.cli import main

if __name__ == "__main__":
    warnings.simplefilter("always", DeprecationWarning)
    warnings.warn(
        "Running HunterX via python hunterx.py is deprecated. "
        "Use the 'hunterx' command directly instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    sys.exit(main())
