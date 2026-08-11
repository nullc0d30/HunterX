# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Toolchain acceptance suite (Sprint 034.5).

End-to-end chains across the composed platform driven by authoritative
fixtures: recon → DNS → probe → crawl → content → vulnerability tooling →
verification. No binary is executed; the adapter/parser/normalizer contract is
the subject under test, so the chains prove that intelligence flows from one
stage to the next with provenance preserved.
"""
