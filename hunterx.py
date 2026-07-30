# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
# Backward-compatible entry point — delegates to hunterx package

import sys
import os
import warnings

sys.path.insert(0, os.path.dirname(__file__))

from hunterx.cli import main

if __name__ == "__main__":
    warnings.simplefilter("always", DeprecationWarning)
    warnings.warn(
        "Running HunterX via python hunterx.py is deprecated. "
        "Use the 'hunterx' command directly instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    main()
