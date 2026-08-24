# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Provider Manager with failover support.

This module provides a provider manager that can handle failover between
multiple AI providers (e.g., OpenRouter -> LM Studio -> Ollama -> deterministic).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

from hunterx.config.settings import AISettings
from hunterx.domain.ports.services import AIPort
from hunterx.domain.model_attacker.enums import AIFailureCategory
from hunterx.infrastructure.ai.factory import build_ai_client, _KNOWN_PROVIDERS
from hunterx.infrastructure.ai.providers import classify_ai_error
from hunterx.infrastructure.ai.null import NullAIClient
from hunterx.domain.exceptions import ConfigurationError


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Configuration for a single AI provider."""
    name: str
    settings: AISettings
    priority: int = 0  # Lower = higher priority


class ProviderManager:
    """Manages multiple AI providers with automatic failover.

    The provider manager maintains a prioritized list of AI providers and
    automatically fails over to the next available provider when the current
    one fails or becomes unavailable.

    State machine:
    HEALTHY -> RATE_LIMITED -> COOLDOWN -> RETRY -> HEALTHY
    If provider remains unavailable -> FAILOVER to next provider
    """

    def __init__(self, provider_configs: list[ProviderConfig] | None = None):
        self._providers: list[tuple[ProviderConfig, AIPort]] = []
        self._current_index = 0
        self._cooldown_until: float = 0.0
        self._cooldown_events = 0
        self._fallback_decisions = 0
        self._deterministic_decisions = 0
        self._last_attempt_at = 0.0
        self._min_interval = 1.0
        self._backoff = 5.0
        self._max_cooldown = 60.0
        self._cooldown_events = 0

        if provider_configs:
            for config in provider_configs:
                self.add_provider(config)

    def add_provider(self, config: ProviderConfig) -> None:
        """Add a provider to the failover chain."""
        if config.name not in _KNOWN_PROVIDERS:
            raise ConfigurationError(f"Unknown provider: {config.name}")

        # Create settings for this provider
        settings = AISettings(
            provider=config.name,
            model=config.settings.model,
            base_url=config.settings.base_url,
            timeout=config.settings.timeout,
        )
        # Copy API keys
        for key in ["openai_key", "anthropic_key", "openrouter_key", "gemini_key",
                    "deepseek_key", "grok_key", "lmstudio_key", "ollama_key",
                    "openai_compatible_key"]:
            if hasattr(config.settings, key):
                setattr(config.settings, key, getattr(config.settings, key))

        # Create the client
        try:
            client = build_ai_client(config.settings)
            self._providers.append((config, client))
            # Sort by priority (lower = higher priority)
            self._providers.sort(key=lambda x: x[0].priority)
        except Exception as exc:
            raise ConfigurationError(f"Failed to create {config.name} client: {exc}") from exc

    @property
    def current_provider(self) -> Optional[AIPort]:
        """Get the current active provider."""
        if not self._providers:
            return None
        return self._providers[self._current_index][1]

    @property
    def current_provider_name(self) -> str:
        """Get the name of the current provider."""
        if not self._providers:
            return "none"
        return self._providers[self._current_index][0].name

    @property
    def current_provider_config(self) -> Optional[ProviderConfig]:
        """Get the current provider's configuration."""
        if not self._providers:
            return None
        return self._providers[self._current_index][0]

    def _failover(self) -> bool:
        """Attempt to failover to the next provider.

        Returns True if failover succeeded, False if no more providers available.
        """
        if self._current_index + 1 < len(self._providers):
            self._current_index += 1
            self._cooldown_until = 0.0
            self._cooldown_events += 1
            return True
        return False

    def _enter_cooldown(self, exc: Exception, *, auth_failure: bool = False) -> None:
        """Enter cooldown after a rate limit or error."""
        from hunterx.infrastructure.ai.providers import _retry_after_seconds
        import random

        retry_after = float(getattr(exc, "retry_after", 0.0) or 0.0)
        if retry_after > 0:
            cooldown = retry_after
        else:
            cooldown = self._backoff * (2 ** self._cooldown_events)
            cooldown = cooldown + random.uniform(0.0, min(5.0, cooldown))

        cooldown = min(cooldown, self._max_cooldown)
        if auth_failure:
            cooldown = max(cooldown, self._max_cooldown)

        self._cooldown_events += 1
        self._cooldown_until = max(self._cooldown_until, time.monotonic() + cooldown)

    def rate_limited(self) -> bool:
        """Return True if currently in cooldown."""
        return time.monotonic() < self._cooldown_until

    def cooldown_remaining_s(self) -> float:
        """Return remaining cooldown time in seconds."""
        return max(0.0, self._cooldown_until - time.monotonic())

    def suggest(self, mission: Any, candidates: list[Any]) -> Any:
        """Get a suggestion from the current provider with automatic failover."""
        from hunterx.application.ai_suggestion import AISuggestion
        import dataclasses

        # Check if we're in cooldown
        if self.rate_limited():
            self._deterministic_decisions += 1
            self._fallback_decisions += 1
            remaining = int(self.cooldown_remaining_s())
            return AISuggestion(
                error=f"AI rate-limited; deterministic fallback for {remaining}s",
                http_status=429,
                fallback=True,
                cooldown=True,
                deterministic=True,
            )

        # Free-tier throttling
        now = time.monotonic()
        if now - self._last_attempt_at < 1.0:
            self._deterministic_decisions += 1
            return AISuggestion(error="AI request throttled (free-tier budget); deterministic decision", deterministic=True)

        self._last_attempt_at = time.monotonic()

        # Try current provider, failover on failure
        for attempt in range(len(self._providers)):
            provider = self.current_provider
            if provider is None:
                break

            from hunterx.application.ai_suggestion import AISuggestion
            from hunterx.domain.model_attacker.enums import AIFailureCategory
            from hunterx.infrastructure.ai.providers import classify_ai_error
            import dataclasses

            candidate_ids = [getattr(c, "action_id", "") for c in candidates]
            prompt = self._build_prompt(mission, candidates)

            started = time.monotonic()
            try:
                response = self.current_provider.complete(prompt, model=self._get_model())
            except TimeoutError:
                latency = int((time.monotonic() - started) * 1000)
                self._fallback_decisions += 1
                if self._failover():
                    continue  # Try next provider
                return AISuggestion(
                    invoked=True,
                    latency_ms=latency,
                    error="AI request timed out; deterministic fallback",
                    timeout=True,
                    fallback=True,
                )
            except Exception as exc:
                latency = int((time.monotonic() - started) * 1000)
                category, msg = classify_ai_error(exc)

                if category == "rate_limited":
                    self._enter_cooldown(exc)
                    if self._failover():
                        continue  # Try next provider
                    return AISuggestion(
                        invoked=True,
                        latency_ms=latency,
                        error=f"AI rate limited; fallback for {self.cooldown_remaining_s():.0f}s",
                        http_status=429,
                        fallback=True,
                        cooldown=True,
                        deterministic=True,
                    )
                elif category in ("connection_refused", "connection_error", "authentication_error", "model_unavailable"):
                    if self._failover():
                        continue  # Try next provider
                    return AISuggestion(
                        invoked=True,
                        latency_ms=latency,
                        error=f"AI error ({category}): {msg}; deterministic fallback",
                        fallback=True,
                        deterministic=True,
                    )
                else:
                    self._fallback_decisions += 1
                    return AISuggestion(
                        invoked=True,
                        latency_ms=latency,
                        error=f"AI request failed: {exc}; deterministic fallback",
                        http_status=0,
                        fallback=True,
                    )

            latency = int((time.monotonic() - started) * 1000)

            # Parse response
            from hunterx.application.ai_suggestion import _parse_suggestion
            parsed, error = _parse_suggestion(response)
            if parsed is None:
                self._fallback_decisions += 1
                if self._failover():
                    continue
                return AISuggestion(
                    invoked=True,
                    latency_ms=latency,
                    error=f"{error}; deterministic fallback",
                    raw=response,
                    fallback=True,
                )

            action_id = str(parsed.get("suggested_action_id", ""))
            reason = str(parsed.get("reason", ""))

            # Validate against candidates
            candidate_ids = [getattr(c, "action_id", "") for c in candidates]
            if action_id not in candidate_ids:
                self._fallback_decisions += 1
                return AISuggestion(
                    invoked=True,
                    latency_ms=latency,
                    raw=response,
                    error=f"AI suggested '{action_id}' which is not an available candidate (valid: {', '.join(candidate_ids)}); deterministic fallback",
                    fallback=True,
                )

            return AISuggestion(invoked=True, latency_ms=latency, raw=response, action_id=action_id, reason=reason)

        # All providers exhausted
        self._deterministic_decisions += 1
        return AISuggestion(error="All AI providers exhausted; deterministic fallback", deterministic=True)

    def _get_model(self) -> Optional[str]:
        """Get the model for the current provider."""
        if self.current_provider_config:
            return self.current_provider_config.settings.model
        return None

    def _build_prompt(self, mission: Any, candidates: list) -> str:
        """Build a prompt for the AI model."""
        from hunterx.application.ai_suggestion import _build_prompt
        return _build_prompt(mission, candidates)

    def check(self) -> bool:
        """Check if current provider is healthy."""
        provider = self.current_provider
        if provider is None:
            return False
        return provider.check()

    def telemetry(self) -> dict[str, Any]:
        """Return telemetry data."""
        return {
            "provider": self.current_provider_name,
            "model": self._get_model() or "",
            "cooldown_events": self._cooldown_events,
            "fallback_decisions": self._fallback_decisions,
            "deterministic_decisions": self._deterministic_decisions,
        }

    def reset_rate_limit(self) -> None:
        """Clear the rate-limit cooldown."""
        self._cooldown_until = 0.0
        self._current_index = 0  # Reset to primary provider