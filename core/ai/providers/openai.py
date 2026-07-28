from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..adapters.base import BaseHTTPAdapter
from ..models import ModelCapability, ModelInfo


class OpenAIProvider(BaseHTTPAdapter):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        config.setdefault("api_endpoint", config.get("api_endpoint", "https://api.openai.com"))
        config.setdefault("model", config.get("model", "gpt-4o"))
        config.setdefault("embedding_model", "text-embedding-ada-002")
        super().__init__(config)

    def provider_name(self) -> str:
        return "openai"

    def provider_version(self) -> str:
        return "1.0.0"

    def model_list(self) -> List[ModelInfo]:
        default_models = [
            ModelInfo(
                id="gpt-4o", name="GPT-4o", provider="openai",
                capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING, ModelCapability.TOOLS,
                              ModelCapability.JSON_MODE, ModelCapability.FUNCTION_CALLING,
                              ModelCapability.SYSTEM_PROMPT, ModelCapability.VISION,
                              ModelCapability.IMAGES],
                context_length=128000,
                pricing_prompt=2.5e-6, pricing_completion=1.0e-5,
                description="OpenAI GPT-4o multimodal model",
            ),
            ModelInfo(
                id="gpt-4o-mini", name="GPT-4o Mini", provider="openai",
                capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING, ModelCapability.TOOLS,
                              ModelCapability.JSON_MODE, ModelCapability.FUNCTION_CALLING,
                              ModelCapability.SYSTEM_PROMPT],
                context_length=128000,
                pricing_prompt=1.5e-7, pricing_completion=6.0e-7,
                description="OpenAI GPT-4o Mini cost-optimized model",
            ),
            ModelInfo(
                id="text-embedding-ada-002", name="Text Embedding ADA 002", provider="openai",
                capabilities=[ModelCapability.EMBEDDINGS],
                context_length=8191,
                pricing_prompt=1.0e-7, pricing_completion=0,
                description="OpenAI text embeddings model",
            ),
        ]

        try:
            data = self._request("GET", "v1/models")
            models = data.get("data", [])
            if models:
                return [
                    ModelInfo(
                        id=m["id"],
                        name=m["id"],
                        provider="openai",
                        capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING],
                        context_length=m.get("context_length", 4096),
                    )
                    for m in models[:50]
                ]
        except Exception:
            pass

        return default_models

    def supports_embeddings(self) -> bool:
        return True

    def supports_vision(self) -> bool:
        return True

    def supports_images(self) -> bool:
        return True

    def _embeddings_endpoint(self) -> str:
        return "v1/embeddings"
