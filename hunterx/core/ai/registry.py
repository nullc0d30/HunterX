from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
import sys
import threading
from typing import Any, Dict, List, Optional, Type

from ...utils.utils import logger
from .exceptions import ProviderNotFoundError
from .models import ProviderStatus
from .provider import AIProvider


class ProviderRegistry:
    _instance: Optional[ProviderRegistry] = None
    _lock: threading.RLock = threading.RLock()

    def __new__(cls) -> ProviderRegistry:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._providers: Dict[str, Type[AIProvider]] = {}
                    cls._instance._instances: Dict[str, AIProvider] = {}
                    cls._instance._configs: Dict[str, Dict[str, Any]] = {}
                    cls._instance._lock = threading.RLock()
        return cls._instance

    def register(
        self,
        provider_class: Type[AIProvider],
        name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            provider_name = name or self._resolve_provider_name(provider_class)
            if not issubclass(provider_class, AIProvider):
                raise TypeError(f"{provider_class.__name__} must extend AIProvider")
            self._providers[provider_name] = provider_class
            if config:
                self._configs[provider_name] = config
            logger.debug(f"ProviderRegistry: registered '{provider_name}' ({provider_class.__name__})")

    def unregister(self, name: str) -> None:
        with self._lock:
            self._providers.pop(name, None)
            self._instances.pop(name, None)
            self._configs.pop(name, None)

    def get(self, name: str, auto_initialize: bool = True) -> AIProvider:
        with self._lock:
            if name in self._instances and self._instances[name].initialized:
                return self._instances[name]

            provider_class = self._providers.get(name)
            if not provider_class:
                raise ProviderNotFoundError(name)

            config = self._configs.get(name, {})
            instance = provider_class(config)
            if auto_initialize:
                instance.initialize()
            self._instances[name] = instance
            return instance

    def get_class(self, name: str) -> Type[AIProvider]:
        provider_class = self._providers.get(name)
        if not provider_class:
            raise ProviderNotFoundError(name)
        return provider_class

    def list(self) -> List[str]:
        with self._lock:
            return sorted(self._providers.keys())

    def list_with_status(self) -> List[Dict[str, Any]]:
        with self._lock:
            results: List[Dict[str, Any]] = []
            for name in self._providers:
                try:
                    instance = self.get(name)
                    health = instance.health()
                    results.append({
                        "name": name,
                        "class": type(instance).__name__,
                        "available": health.available,
                        "healthy": health.healthy,
                        "initialized": instance.initialized,
                        "model_count": health.model_count,
                    })
                except Exception as e:
                    results.append({
                        "name": name,
                        "class": self._providers[name].__name__,
                        "available": False,
                        "healthy": False,
                        "initialized": False,
                        "error": str(e),
                    })
            return results

    def health_check(self, name: str) -> ProviderStatus:
        instance = self.get(name)
        return instance.health()

    def health_check_all(self) -> Dict[str, ProviderStatus]:
        results: Dict[str, ProviderStatus] = {}
        for name in self.list():
            try:
                results[name] = self.health_check(name)
            except Exception as e:
                results[name] = ProviderStatus(
                    provider=name,
                    available=False,
                    healthy=False,
                    error=str(e),
                )
        return results

    def shutdown_all(self) -> None:
        with self._lock:
            for name, instance in self._instances.items():
                try:
                    instance.shutdown()
                except Exception as e:
                    logger.debug(f"ProviderRegistry: shutdown {name} failed: {e}")
            self._instances.clear()

    def discover(self, paths: Optional[List[str]] = None) -> int:
        discovered = 0
        search_paths = paths or [os.path.join(os.path.dirname(__file__), "providers")]

        for search_path in search_paths:
            if not os.path.isdir(search_path):
                continue
            sys.path.insert(0, os.path.dirname(search_path))
            for importer, modname, ispkg in pkgutil.iter_modules([search_path]):
                if ispkg or modname.startswith("_"):
                    continue
                try:
                    module = importlib.import_module(f"core.ai.providers.{modname}")
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (
                            issubclass(obj, AIProvider)
                            and obj is not AIProvider
                            and hasattr(obj, "provider_name")
                        ):
                            provider_name = obj.provider_name(obj)
                            if provider_name and provider_name not in self._providers:
                                self.register(obj)
                                discovered += 1
                except Exception as e:
                    logger.debug(f"ProviderRegistry: skip {modname}: {e}")

        return discovered

    def _resolve_provider_name(self, provider_class: Type[AIProvider]) -> str:
        try:
            instance = provider_class()
            return instance.provider_name()
        except Exception:
            return provider_class.__name__.replace("Provider", "").lower()

    def __contains__(self, name: str) -> bool:
        return name in self._providers
