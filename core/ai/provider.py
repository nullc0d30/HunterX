from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, Dict, Generator, List, Optional

from .exceptions import CircuitBreaker, RetryHandler
from .models import (
    ChatRequest,
    ChatResponse,
    CompletionRequest,
    CompletionResponse,
    EmbeddingRequest,
    EmbeddingResponse,
    ModelCapability,
    ModelInfo,
    ProviderStatus,
    StreamingChunk,
)


class AIProvider(ABC):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}
        self._initialized = False
        self._circuit_breaker: Optional[CircuitBreaker] = None
        self._retry_handler: Optional[RetryHandler] = None

    @abstractmethod
    def initialize(self) -> None:
        ...

    @abstractmethod
    def shutdown(self) -> None:
        ...

    @abstractmethod
    def health(self) -> ProviderStatus:
        ...

    @abstractmethod
    def chat(self, request: ChatRequest) -> ChatResponse:
        ...

    @abstractmethod
    def complete(self, request: CompletionRequest) -> CompletionResponse:
        ...

    def stream(self, request: ChatRequest) -> Generator[StreamingChunk, None, None]:
        raise NotImplementedError(f"{self.provider_name()} does not support streaming")

    async def astream(self, request: ChatRequest) -> AsyncGenerator[StreamingChunk, None]:
        raise NotImplementedError(f"{self.provider_name()} does not support async streaming")

    @abstractmethod
    def embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        ...

    @abstractmethod
    def tokenize(self, text: str) -> List[int]:
        ...

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        ...

    @abstractmethod
    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        ...

    @abstractmethod
    def supports_streaming(self) -> bool:
        ...

    @abstractmethod
    def supports_tools(self) -> bool:
        ...

    @abstractmethod
    def supports_images(self) -> bool:
        ...

    @abstractmethod
    def supports_embeddings(self) -> bool:
        ...

    @abstractmethod
    def supports_json_mode(self) -> bool:
        ...

    @abstractmethod
    def supports_function_calling(self) -> bool:
        ...

    @abstractmethod
    def supports_reasoning(self) -> bool:
        ...

    @abstractmethod
    def supports_system_prompt(self) -> bool:
        ...

    @abstractmethod
    def supports_vision(self) -> bool:
        ...

    @abstractmethod
    def provider_name(self) -> str:
        ...

    @abstractmethod
    def provider_version(self) -> str:
        ...

    @abstractmethod
    def model_list(self) -> List[ModelInfo]:
        ...

    def get_capabilities(self) -> List[ModelCapability]:
        caps: List[ModelCapability] = []
        if self.supports_streaming():
            caps.append(ModelCapability.STREAMING)
        if self.supports_tools():
            caps.append(ModelCapability.TOOLS)
        if self.supports_images():
            caps.append(ModelCapability.IMAGES)
        if self.supports_embeddings():
            caps.append(ModelCapability.EMBEDDINGS)
        if self.supports_json_mode():
            caps.append(ModelCapability.JSON_MODE)
        if self.supports_function_calling():
            caps.append(ModelCapability.FUNCTION_CALLING)
        if self.supports_reasoning():
            caps.append(ModelCapability.REASONING)
        if self.supports_system_prompt():
            caps.append(ModelCapability.SYSTEM_PROMPT)
        if self.supports_vision():
            caps.append(ModelCapability.VISION)
        caps.append(ModelCapability.CHAT)
        caps.append(ModelCapability.COMPLETION)
        return caps

    @property
    def initialized(self) -> bool:
        return self._initialized

    def __repr__(self) -> str:
        return f"{self.provider_name()} v{self.provider_version()} (initialized={self._initialized})"
