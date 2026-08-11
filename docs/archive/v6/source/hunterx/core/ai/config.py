from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ...utils.utils import logger
from .models import AIConfigProfile


@dataclass
class AIConfig:
    default_provider: str = ""
    default_model: str = ""
    profiles: Dict[str, AIConfigProfile] = field(default_factory=dict)
    enabled: bool = True
    cache_enabled: bool = True
    cache_ttl: int = 3600
    cache_max_size: int = 10000
    metrics_enabled: bool = True
    log_prompts: bool = False
    log_responses: bool = False
    log_sensitive: bool = False
    enable_streaming: bool = True
    enable_fallback: bool = True
    max_retries: int = 3
    request_timeout: float = 60.0
    rate_limit_rpm: int = 60
    encrypt_keys: bool = True
    environment: str = "production"

    def get_profile(self, name: str = "default") -> AIConfigProfile:
        if name in self.profiles:
            return self.profiles[name]
        return AIConfigProfile(name="default")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "default_provider": self.default_provider,
            "default_model": self.default_model,
            "profiles": {k: v.__dict__ for k, v in self.profiles.items()},
            "enabled": self.enabled,
            "cache_enabled": self.cache_enabled,
            "cache_ttl": self.cache_ttl,
            "metrics_enabled": self.metrics_enabled,
            "enable_streaming": self.enable_streaming,
            "enable_fallback": self.enable_fallback,
            "max_retries": self.max_retries,
            "request_timeout": self.request_timeout,
            "rate_limit_rpm": self.rate_limit_rpm,
            "environment": self.environment,
        }


class AIConfigManager:
    _instance: Optional[AIConfig] = None

    @classmethod
    def load(cls, path: Optional[str] = None) -> AIConfig:
        if cls._instance is not None:
            return cls._instance

        config = AIConfig()

        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                cls._apply_dict(config, data)
                logger.info(f"AIConfig: loaded from {path}")
            except Exception as e:
                logger.debug(f"AIConfig: failed to load {path}: {e}")

        cls._apply_env_overrides(config)
        cls._instance = config
        return config

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    @classmethod
    def _apply_dict(cls, config: AIConfig, data: Dict[str, Any]) -> None:
        for key, value in data.items():
            if key == "profiles" and isinstance(value, dict):
                for pname, pdata in value.items():
                    if isinstance(pdata, dict):
                        config.profiles[pname] = AIConfigProfile(name=pname, **pdata)
            elif hasattr(config, key):
                setattr(config, key, value)

    @classmethod
    def _apply_env_overrides(cls, config: AIConfig) -> None:
        mapping = {
            "HUNTERX_AI_DEFAULT_PROVIDER": "default_provider",
            "HUNTERX_AI_DEFAULT_MODEL": "default_model",
            "HUNTERX_AI_ENABLED": "enabled",
            "HUNTERX_AI_CACHE_ENABLED": "cache_enabled",
            "HUNTERX_AI_CACHE_TTL": "cache_ttl",
            "HUNTERX_AI_METRICS_ENABLED": "metrics_enabled",
            "HUNTERX_AI_ENABLE_STREAMING": "enable_streaming",
            "HUNTERX_AI_ENABLE_FALLBACK": "enable_fallback",
            "HUNTERX_AI_MAX_RETRIES": "max_retries",
            "HUNTERX_AI_REQUEST_TIMEOUT": "request_timeout",
            "HUNTERX_AI_RATE_LIMIT_RPM": "rate_limit_rpm",
            "HUNTERX_AI_LOG_PROMPTS": "log_prompts",
            "HUNTERX_AI_LOG_RESPONSES": "log_responses",
        }
        for env_key, config_key in mapping.items():
            value = os.environ.get(env_key)
            if value is not None:
                current = getattr(config, config_key, None)
                if isinstance(current, bool):
                    setattr(config, config_key, value.lower() in ("1", "true", "yes"))
                elif isinstance(current, int):
                    try:
                        setattr(config, config_key, int(value))
                    except ValueError:
                        pass
                elif isinstance(current, float):
                    try:
                        setattr(config, config_key, float(value))
                    except ValueError:
                        pass
                else:
                    setattr(config, config_key, value)

        for env_key, provider_prefix in [("HUNTERX_AI_OPENAI_KEY", "openai"), ("HUNTERX_AI_ANTHROPIC_KEY", "anthropic"), ("HUNTERX_AI_OPENROUTER_KEY", "openrouter"), ("HUNTERX_AI_GEMINI_KEY", "gemini"), ("HUNTERX_AI_DEEPSEEK_KEY", "deepseek"), ("HUNTERX_AI_GROK_KEY", "grok")]:
            api_key = os.environ.get(env_key)
            if api_key:
                if provider_prefix not in config.profiles:
                    config.profiles[provider_prefix] = AIConfigProfile(name=provider_prefix, provider=provider_prefix)
                config.profiles[provider_prefix].api_key = api_key
