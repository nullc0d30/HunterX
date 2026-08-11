# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Toolchain certification unit suite (Sprint 034.5).

Validates the complete adapter/parser/normalizer/contract of the toolchain
against authoritative fixtures. No external binary is required: adapters are
driven through a fake runner that returns canned tool output, so the contract
(argument builder, parser, normalizer, failure classification, chaining) is
certified independently of binary availability.
"""
