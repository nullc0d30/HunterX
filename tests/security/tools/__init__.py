# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Toolchain security certification (Sprint 034.5).

Pins the security properties of the certified toolchain: structured argv (no
shell interpolation), argument/option injection guards, hostile-output handling,
raw-secret non-persistence, candidate-not-finding boundaries and the masking
regression fixed during this sprint.
"""
