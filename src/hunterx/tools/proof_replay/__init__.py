# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Safe proof replay tools.

In-process, deterministic proof-replay adapters that integrate with the Tool
Integration SDK lifecycle. Replays are structured proof demonstrations with
bounded inputs — never arbitrary executable scripts or weaponized payloads.
"""

from __future__ import annotations

from hunterx.tools.proof_replay.adapters import (
    REPLAY_RESULT_KEY,
    REPLAY_VERDICT_KEY,
    ProofReplayAdapter,
    proof_replay_adapters,
)
from hunterx.tools.proof_replay.registry import (
    PROOF_REPLAY_TOOL_IDS,
    register_proof_replay_adapters,
)

__all__ = [
    "PROOF_REPLAY_TOOL_IDS",
    "ProofReplayAdapter",
    "REPLAY_RESULT_KEY",
    "REPLAY_VERDICT_KEY",
    "proof_replay_adapters",
    "register_proof_replay_adapters",
]
