# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Enums for the universal capability-finding lifecycle."""

from __future__ import annotations

from enum import StrEnum


class ReproductionVerdict(StrEnum):
    """Classification of an isolated replay series.

    A candidate is ``REPRODUCIBLE`` only when every replay attempt confirms
    the differential signal. ``INTERMITTENT`` covers a confirmed subset.
    ``NOT_REPRODUCIBLE`` means the signal could not be re-observed on any
    isolated replay.
    """

    REPRODUCIBLE = "reproducible"
    INTERMITTENT = "intermittent"
    NOT_REPRODUCIBLE = "not_reproducible"


__all__ = ["ReproductionVerdict"]
