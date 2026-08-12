# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""HunterX engineering platform.

DevSecOps, CI/CD, quality-gate, release-engineering and supply-chain-security
tooling. This package is **not shipped** with the ``hunterxsec`` distribution; it
lives at the repository root and is invoked by GitHub Actions workflows and by
developers locally. Every gate and report is deterministic and testable: tool
invocation goes through :mod:`eng.tooling` so the logic can be validated with
fakes.
"""
