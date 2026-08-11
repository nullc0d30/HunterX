# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Run the architecture linter: ``python -m hunterx.architecture``."""

from __future__ import annotations

import sys

from hunterx.architecture.cli import main

if __name__ == "__main__":
    sys.exit(main())
