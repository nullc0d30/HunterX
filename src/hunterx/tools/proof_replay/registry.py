# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Proof replay adapter registry.

Registers the deterministic safe proof-replay adapters on the Tool Integration
SDK :class:`ExecutionEngine`. Every replay flows through the SDK lifecycle —
proof code never invokes ``subprocess`` directly and never executes outside the
already-gated parameters.
"""

from __future__ import annotations

from collections.abc import Mapping

from hunterx.tools.proof_replay.adapters import ProofReplayAdapter, proof_replay_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

#: Proof-replay tool ids.
PROOF_REPLAY_TOOL_IDS = ("proof-replay",)


def register_proof_replay_adapters(engine: ExecutionEngine) -> Mapping[str, ProofReplayAdapter]:
    """Register the proof-replay adapters on ``engine``.

    Args:
        engine: the SDK execution engine.

    Returns:
        The mapping of tool id → adapter registered.

    """
    adapters = proof_replay_adapters()
    for tool_id, adapter in adapters.items():
        engine.register_adapter(tool_id, adapter)
    return adapters


__all__ = ["PROOF_REPLAY_TOOL_IDS", "ProofReplayAdapter", "register_proof_replay_adapters"]
