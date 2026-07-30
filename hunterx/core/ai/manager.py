from __future__ import annotations

import time
from typing import Any, Dict, Generator, List, Optional

from ...utils.utils import logger
from .cache import AICache
from .config import AIConfig, AIConfigManager
from .conversation import ConversationManager
from .exceptions import AIError, ConfigurationError
from .factory import AIFactory
from .metrics import AIMetricsCollector
from .middleware import MiddlewarePipeline
from .models import (
    ChatRequest,
    ChatResponse,
    EmbeddingRequest,
    EmbeddingResponse,
    Message,
    ModelInfo,
    ProviderStatus,
    StreamingChunk,
)
from .provider import AIProvider
from .registry import ProviderRegistry


class AIManager:
    def __init__(
        self,
        registry: Optional[ProviderRegistry] = None,
        factory: Optional[AIFactory] = None,
        config: Optional[AIConfig] = None,
        cache: Optional[AICache] = None,
        metrics: Optional[AIMetricsCollector] = None,
        conversation: Optional[ConversationManager] = None,
        middleware: Optional[MiddlewarePipeline] = None,
    ):
        self._config = config or AIConfigManager.load()
        self._registry = registry or ProviderRegistry()
        self._factory = factory or AIFactory(self._registry)
        self._cache = cache
        self._metrics = metrics or AIMetricsCollector()
        self._conversation = conversation or ConversationManager()
        self._middleware = middleware or MiddlewarePipeline()

        if not self._config.enabled:
            logger.info("AIManager: AI subsystem is disabled")

    def chat(
        self,
        messages: List[Message],
        model: str = "",
        provider: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        stream: bool = False,
        json_mode: bool = False,
        tools: Optional[List[Dict[str, Any]]] = None,
        profile: Optional[str] = None,
    ) -> ChatResponse:
        if not self._config.enabled:
            raise ConfigurationError("AI subsystem is disabled")

        request = ChatRequest(
            messages=messages,
            model=model,
            provider=provider,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=stream,
            json_mode=json_mode,
            tools=tools,
        )

        return self._execute_with_middleware("chat", request, profile)

    def complete(
        self,
        prompt: str,
        model: str = "",
        provider: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        profile: Optional[str] = None,
    ) -> ChatResponse:
        messages = [Message.user(prompt)]
        return self.chat(
            messages=messages,
            model=model,
            provider=provider,
            temperature=temperature,
            max_tokens=max_tokens,
            profile=profile,
        )

    def stream(
        self,
        messages: List[Message],
        model: str = "",
        provider: str = "",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        profile: Optional[str] = None,
    ) -> Generator[StreamingChunk, None, None]:
        request = ChatRequest(
            messages=messages,
            model=model,
            provider=provider,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )
        provider_instance = self._resolve_provider(provider, profile)

        if not provider_instance.supports_streaming():
            response = provider_instance.chat(request)
            yield StreamingChunk(content=response.content, finish_reason=response.finish_reason, usage=response.usage)
            return

        start = time.monotonic()
        try:
            for chunk in provider_instance.stream(request):
                yield chunk
        finally:
            duration = (time.monotonic() - start) * 1000
            self._metrics.record_streaming_duration(provider_instance.provider_name(), duration)

    def embeddings(
        self,
        texts: List[str],
        model: str = "",
        provider: str = "",
        profile: Optional[str] = None,
    ) -> EmbeddingResponse:
        request = EmbeddingRequest(input=texts, model=model)
        provider_instance = self._resolve_provider(provider, profile)
        return provider_instance.embeddings(request)

    def count_tokens(self, text: str, provider: str = "", model: str = "") -> int:
        provider_instance = self._resolve_provider(provider)
        return provider_instance.count_tokens(text)

    def estimate_cost(
        self,
        prompt_tokens: int,
        completion_tokens: int,
        provider: str = "",
    ) -> float:
        provider_instance = self._resolve_provider(provider)
        return provider_instance.estimate_cost(prompt_tokens, completion_tokens)

    def health(self, provider: str = "") -> ProviderStatus:
        provider_instance = self._resolve_provider(provider)
        return provider_instance.health()

    def health_all(self) -> Dict[str, ProviderStatus]:
        return self._registry.health_check_all()

    def list_providers(self) -> List[Dict[str, Any]]:
        return self._registry.list_with_status()

    def list_models(self, provider: str = "") -> List[ModelInfo]:
        provider_instance = self._resolve_provider(provider)
        return provider_instance.model_list()

    def get_conversation(self, conversation_id: str):
        return self._conversation.get_conversation(conversation_id)

    def create_conversation(self, system_prompt: str = ""):
        return self._conversation.create(system_prompt=system_prompt)

    def get_metrics(self) -> Dict[str, Any]:
        return self._metrics.get_summary()

    def get_cache_stats(self) -> Dict[str, Any]:
        if self._cache:
            return self._cache.get_stats()
        return {"enabled": False}

    def clear_cache(self) -> None:
        if self._cache:
            self._cache.clear()

    def shutdown(self) -> None:
        self._registry.shutdown_all()
        if self._cache:
            self._cache.close()

    def _resolve_provider(self, provider: str = "", profile: Optional[str] = None) -> AIProvider:
        if profile:
            profile_config = self._config.get_profile(profile)
            if profile_config.provider:
                return self._factory.create_from_profile(profile_config)

        if provider:
            return self._factory.create(provider)

        return self._factory.create_default()

    def _execute_with_middleware(
        self,
        method: str,
        request: Any,
        profile: Optional[str] = None,
    ) -> Any:
        provider_instance = self._resolve_provider(request.provider, profile)
        request.provider = provider_instance.provider_name()

        profile_config = None
        if profile:
            profile_config = self._config.get_profile(profile)

        if not request.model and profile_config and profile_config.model:
            request.model = profile_config.model

        if (
            self._config.log_prompts
            and not self._config.log_sensitive
        ):
            logger.debug(f"AIManager.{method}: provider={request.provider} model={request.model}")

        def execute() -> Any:
            if method == "chat":
                return provider_instance.chat(request)
            raise ValueError(f"Unknown method: {method}")

        try:
            start = time.monotonic()
            response = self._middleware.execute(execute, provider_instance.provider_name())
            duration = (time.monotonic() - start) * 1000
            response.latency_ms = duration

            if self._metrics:
                usage = response.usage
                if usage:
                    self._metrics.record_request(
                        provider=provider_instance.provider_name(),
                        model=request.model or "",
                        duration_ms=duration,
                        prompt_tokens=usage.prompt_tokens,
                        completion_tokens=usage.completion_tokens,
                        success=True,
                    )
                else:
                    self._metrics.record_request(
                        provider=provider_instance.provider_name(),
                        model=request.model or "",
                        duration_ms=duration,
                        success=True,
                    )

            if self._config.log_responses and not self._config.log_sensitive:
                logger.debug(f"AIManager: response from {request.provider} ({duration:.0f}ms)")

            return response

        except AIError as e:
            if self._metrics:
                self._metrics.record_request(
                    provider=provider_instance.provider_name(),
                    model=request.model or "",
                    duration_ms=0,
                    success=False,
                    error=str(e),
                )
            raise

    def __enter__(self) -> "AIManager":
        return self

    def __exit__(self, *args: Any) -> None:
        self.shutdown()
