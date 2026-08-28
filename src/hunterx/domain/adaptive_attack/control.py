# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive rate control state machine.

Phase 2. The controller is the "aggressive but bounded" heart of the attack
engine. It transitions through :class:`AttackState` values purely from observed
target-feedback signals and derives bounded execution controls:

    * aggression level (how much payload depth each probe uses),
    * pacing (delay between attack steps),
    * concurrency limit (how many parallel attack steps),
    * backoff (exponential, capped),
    * strategic retry (bounded attempts, only for retryable signals).

Healthy targets maintain/increase controlled aggression; defensive targets
throttle, back off, then gradually recover. Every control is bounded — the
controller can never drive uncontrolled flooding, infinite retries, runaway
concurrency or recursive attack loops.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunterx.domain.adaptive_attack.enums import AggressionLevel, AttackState, FeedbackSignal
from hunterx.shared.time import utcnow_iso

#: Signals that push the state machine toward throttling.
_DEFENSIVE: frozenset[FeedbackSignal] = frozenset(
    signal for signal in FeedbackSignal if signal.is_defensive
)

#: Signals that strongly indicate the target is blocking.
_HARD_DEFENSIVE: frozenset[FeedbackSignal] = frozenset(
    signal for signal in FeedbackSignal if signal.is_hard_defensive
)

#: Signals worth a strategic (bounded) retry.
_RETRYABLE: frozenset[FeedbackSignal] = frozenset(
    signal for signal in FeedbackSignal if signal.is_retryable
)


@dataclass(frozen=True, slots=True)
class AttackControlConfig:
    """Bounded tuning knobs of the adaptive rate controller.

    Attributes:
        max_concurrency: hard ceiling on parallel attack steps.
        min_pacing_s: minimum pacing (0 = no forced delay at NORMAL/AGGRESSIVE).
        max_pacing_s: pacing ceiling enforced in throttled/blocked states.
        pacing_base_s: base pacing applied when throttling.
        pacing_factor: multiplier applied to pacing per defensive step.
        max_backoff_s: backoff ceiling.
        aggressive_after: healthy samples before escalating to AGGRESSIVE.
        recover_after: healthy samples before moving toward RECOVERING.
        resume_after: healthy samples in RECOVERING before RESUMING → NORMAL.
        block_after: consecutive hard-defensive samples before BLOCKED.
        unblock_after: healthy samples in BLOCKED before RESUMING.
        max_retries: bounded retry attempts per attack step.

    """

    max_concurrency: int = 8
    min_pacing_s: float = 0.0
    max_pacing_s: float = 30.0
    pacing_base_s: float = 1.0
    pacing_factor: float = 2.0
    max_backoff_s: float = 60.0
    aggressive_after: int = 3
    recover_after: int = 3
    resume_after: int = 2
    block_after: int = 4
    unblock_after: int = 5
    max_retries: int = 3

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_concurrency", max(1, self.max_concurrency))
        object.__setattr__(self, "max_pacing_s", max(self.min_pacing_s, self.max_pacing_s))
        object.__setattr__(self, "max_retries", max(0, self.max_retries))


class AdaptiveRateController:
    """Target-feedback-driven attack intensity controller.

    Args:
        config: bounded control tuning; ``None`` uses safe defaults.
        state: initial attack state.

    """

    def __init__(
        self,
        config: AttackControlConfig | None = None,
        *,
        state: AttackState = AttackState.NORMAL,
    ) -> None:
        self.config = config if config is not None else AttackControlConfig()
        self._state: AttackState = state
        self._healthy_streak = 0
        self._defensive_streak = 0
        self._hard_streak = 0
        self._escalation = 0
        self._transitions: list[dict[str, str]] = []
        self._last_signal: FeedbackSignal = FeedbackSignal.NORMAL
        self._started_at = utcnow_iso()
        self._last_changed_at = utcnow_iso()

    # -- state --------------------------------------------------------------

    @property
    def state(self) -> AttackState:
        """Return the current attack state."""
        return self._state

    def transition_history(self) -> list[dict[str, str]]:
        """Return the ordered state-transition history."""
        return list(self._transitions)

    def observe(self, signal: FeedbackSignal | str) -> AttackState:
        """Transition the state machine from an observed feedback signal.

        Returns the resulting state. Every transition is driven purely by the
        observed target behavior — never by a fixed tool sequence.
        """
        signal = signal if isinstance(signal, FeedbackSignal) else FeedbackSignal(signal)
        self._last_signal = signal
        defensive = signal in _DEFENSIVE
        hard = signal in _HARD_DEFENSIVE
        if defensive:
            self._healthy_streak = 0
            self._defensive_streak += 1
            self._hard_streak = self._hard_streak + 1 if hard else 0
        else:
            self._healthy_streak += 1
            self._defensive_streak = 0
            self._hard_streak = 0
            self._escalation = min(self._escalation + 1, 99)

        state = self._state
        if state is AttackState.BLOCKED:
            if not defensive and self._healthy_streak >= self.config.unblock_after:
                self._transition(AttackState.RESUMING)
            return self._state

        if self._hard_streak >= self.config.block_after:
            self._transition(AttackState.BLOCKED)
            return self._state

        if state in (AttackState.THROTTLED, AttackState.BACKING_OFF):
            if defensive:
                if hard:
                    self._transition(AttackState.BACKING_OFF)
                elif state is AttackState.BACKING_OFF and not hard:
                    self._transition(AttackState.THROTTLED)
            elif self._healthy_streak >= self.config.recover_after:
                self._transition(AttackState.RECOVERING)
            return self._state

        if state is AttackState.RECOVERING:
            if defensive:
                self._transition(AttackState.THROTTLED)
            elif self._healthy_streak >= self.config.recover_after:
                self._transition(AttackState.RESUMING)
            return self._state

        if state is AttackState.RESUMING:
            if defensive:
                self._transition(AttackState.THROTTLED)
            elif self._healthy_streak >= self.config.resume_after:
                self._transition(AttackState.NORMAL)
            return self._state

        # NORMAL / AGGRESSIVE: healthy escalation, defensive throttling.
        if defensive:
            self._transition(AttackState.THROTTLED)
        elif state is AttackState.NORMAL and self._healthy_streak >= self.config.aggressive_after:
            self._transition(AttackState.AGGRESSIVE)
        return self._state

    def _transition(self, new_state: AttackState) -> None:
        """Apply a state transition (idempotent, records history).

        Defensive streaks persist across transitions so that ``block_after``
        consecutive hard-defensive signals escalate THROTTLED → BACKING_OFF →
        BLOCKED. The healthy streak resets on each transition so every recovery
        phase (RECOVERING → RESUMING → NORMAL) requires its own sustained
        healthy budget — that is what makes aggression restore *gradually*.
        """
        if new_state is self._state:
            return
        self._transitions.append(
            {
                "from": self._state.value,
                "to": new_state.value,
                "at": utcnow_iso(),
                "signal": self._last_signal.value,
            }
        )
        self._state = new_state
        self._healthy_streak = 0
        self._last_changed_at = utcnow_iso()

    # -- derived controls ---------------------------------------------------

    def aggression_level(self) -> AggressionLevel:
        """Return the bounded aggression tier for the current state."""
        state = self._state
        if state is AttackState.AGGRESSIVE:
            return AggressionLevel.HIGH if self._escalation >= 6 else AggressionLevel.MEDIUM
        if state is AttackState.RESUMING:
            return AggressionLevel.MEDIUM
        if state in (AttackState.THROTTLED, AttackState.BACKING_OFF, AttackState.BLOCKED):
            return AggressionLevel.LOW
        if state is AttackState.RECOVERING:
            return AggressionLevel.LOW
        return AggressionLevel.MEDIUM

    def pacing_seconds(self) -> float:
        """Return the pacing (delay between attack steps) for the current state.

        ``0`` means "no forced delay" — the aggressive tiers never invent
        delays, and the throttled tiers always bound the delay.
        """
        state = self._state
        base = self.config.pacing_base_s
        if state in (AttackState.NORMAL, AttackState.AGGRESSIVE):
            return self.config.min_pacing_s
        if state is AttackState.THROTTLED:
            return self._capped_pacing(base)
        if state is AttackState.BACKING_OFF:
            return self._capped_pacing(base * self.config.pacing_factor)
        if state is AttackState.BLOCKED:
            return self._capped_pacing(base * 4.0)
        if state is AttackState.RECOVERING:
            return self._capped_pacing(base * 0.5)
        if state is AttackState.RESUMING:
            return self._capped_pacing(base * 0.25)
        return self.config.min_pacing_s

    def concurrency_limit(self) -> int:
        """Return the bounded concurrent attack-step ceiling."""
        state = self._state
        max_concurrency = self.config.max_concurrency
        if state in (AttackState.NORMAL, AttackState.AGGRESSIVE):
            return max_concurrency
        if state in (AttackState.THROTTLED, AttackState.RECOVERING, AttackState.RESUMING):
            return max(1, max_concurrency // 2)
        return 1  # BACKING_OFF / BLOCKED

    def backoff_seconds(self, attempt: int) -> float:
        """Return the capped exponential backoff for a retry ``attempt``."""
        attempt = max(0, attempt)
        delay = self.config.pacing_base_s * (self.config.pacing_factor**attempt)
        return round(min(self.config.max_backoff_s, max(0.0, delay)), 3)

    def should_retry(self, signal: FeedbackSignal, *, attempts: int) -> bool:
        """Return ``True`` when a bounded strategic retry is permitted."""
        if attempts >= self.config.max_retries:
            return False
        if signal not in _RETRYABLE:
            return False
        # Never retry through an active hard block.
        return self._state is not AttackState.BLOCKED

    def escalate(self) -> AggressionLevel:
        """Return the next aggression tier (bounded by ``MAXIMUM``)."""
        return self.aggression_level().escalate()

    def reset(self) -> None:
        """Reset the controller to ``NORMAL`` with cleared history."""
        self._state = AttackState.NORMAL
        self._healthy_streak = 0
        self._defensive_streak = 0
        self._hard_streak = 0
        self._escalation = 0
        self._transitions = []
        self._last_signal = FeedbackSignal.NORMAL
        self._last_changed_at = utcnow_iso()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the controller state to a JSON-safe mapping."""
        return {
            "state": self._state.value,
            "aggression": self.aggression_level().value,
            "pacing_seconds": self.pacing_seconds(),
            "concurrency_limit": self.concurrency_limit(),
            "backoff_seconds": self.backoff_seconds(0),
            "max_retries": self.config.max_retries,
            "healthy_streak": self._healthy_streak,
            "defensive_streak": self._defensive_streak,
            "hard_streak": self._hard_streak,
            "last_signal": self._last_signal.value,
            "transitions": list(self._transitions),
            "config": {
                "max_concurrency": self.config.max_concurrency,
                "min_pacing_s": self.config.min_pacing_s,
                "max_pacing_s": self.config.max_pacing_s,
                "max_backoff_s": self.config.max_backoff_s,
                "max_retries": self.config.max_retries,
            },
        }

    def _capped_pacing(self, delay: float) -> float:
        """Bound a pacing value to the configured ceiling."""
        return round(min(self.config.max_pacing_s, max(0.0, delay)), 3)


__all__ = ["AdaptiveRateController", "AttackControlConfig"]
