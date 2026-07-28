from __future__ import annotations

import random
import threading
from typing import Any, Dict, List, Optional, Tuple

from ..utils import logger
from .config import AIConfigManager
from .exceptions import ProviderNotFoundError, ProviderUnavailableError
from .models import AIConfigProfile
from .provider import AIProvider
from .registry import ProviderRegistry


class AIFactory:
    _instances: Dict[str, "AIFactory"] = {}
    _lock: threading.RLock = threading.RLock()

    def __init__(self, registry: Optional[ProviderRegistry] = None):
        self._registry = registry or ProviderRegistry()
        self._config = AIConfigManager.load()
        self._fallback_order: List[str] = []
        self._weighted_routes: List[Tuple[str, float]] = []
        self._lock = threading.RLock()

    @classmethod
    def get_instance(cls, name: str = "default") -> "AIFactory":
        if name not in cls._instances:
            with cls._lock:
                if name not in cls._instances:
                    cls._instances[name] = cls()
        return cls._instances[name]

    def create(self, provider_name: str, config: Optional[Dict[str, Any]] = None) -> AIProvider:
        return self._registry.get(provider_name)

    def create_from_profile(self, profile: AIConfigProfile) -> AIProvider:
        if not profile.provider:
            raise ProviderNotFoundError("No provider specified in profile")
        provider = self._registry.get(profile.provider)
        return provider

    def create_default(self) -> AIProvider:
        provider_name = self._config.default_provider
        if provider_name and provider_name in self._registry:
            return self._registry.get(provider_name)
        providers = self._registry.list()
        if not providers:
            raise ProviderNotFoundError("No providers registered")
        return self._registry.get(providers[0])

    def create_with_fallback(self, primary: str, fallback: Optional[str] = None) -> AIProvider:
        try:
            return self._registry.get(primary)
        except (ProviderNotFoundError, ProviderUnavailableError) as e:
            logger.warning(f"Primary provider '{primary}' failed: {e}")
            if fallback:
                try:
                    return self._registry.get(fallback)
                except (ProviderNotFoundError, ProviderUnavailableError) as e2:
                    logger.warning(f"Fallback '{fallback}' also failed: {e2}")
            else:
                for fb in self._fallback_order:
                    try:
                        return self._registry.get(fb)
                    except (ProviderNotFoundError, ProviderUnavailableError):
                        continue
            raise ProviderUnavailableError(f"No available provider (primary={primary}, fallback={fallback})")

    def create_priority(self, providers: List[str]) -> AIProvider:
        for provider_name in providers:
            try:
                return self._registry.get(provider_name)
            except (ProviderNotFoundError, ProviderUnavailableError) as e:
                logger.debug(f"Priority provider '{provider_name}' unavailable: {e}")
                continue
        raise ProviderUnavailableError(f"No available provider in priority list: {providers}")

    def create_weighted(self, routes: List[Tuple[str, float]]) -> AIProvider:
        if not routes:
            raise ProviderNotFoundError("Empty weighted route list")
        providers, weights = zip(*routes)
        total = sum(weights)
        if total <= 0:
            return self._registry.get(routes[0][0])
        pick = random.uniform(0, total)
        cumulative = 0.0
        for provider_name, weight in routes:
            cumulative += weight
            if pick <= cumulative:
                return self._registry.get(provider_name)
        return self._registry.get(routes[-1][0])

    def set_fallback_order(self, order: List[str]) -> None:
        self._fallback_order = order

    def set_weighted_routes(self, routes: List[Tuple[str, float]]) -> None:
        self._weighted_routes = routes

    def create_chain(
        self,
        primary: str,
        fallbacks: Optional[List[str]] = None,
        profile: Optional[AIConfigProfile] = None,
    ) -> AIProvider:
        if profile:
            return self.create_from_profile(profile)
        if fallbacks:
            return self.create_with_fallback(primary, fallbacks[0] if fallbacks else None)
        return self.create(primary)
