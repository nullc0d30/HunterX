from __future__ import annotations

import json
import time
from typing import Any, Dict, Generator, List, Optional

from ..adapters.base import BaseHTTPAdapter
from ..models import (
    ChatRequest,
    ChatResponse,
    CompletionRequest,
    CompletionResponse,
    EmbeddingRequest,
    EmbeddingResponse,
    FinishReason,
    ModelCapability,
    ModelInfo,
    StreamingChunk,
    TokenUsage,
)


class OllamaProvider(BaseHTTPAdapter):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        config.setdefault("api_endpoint", config.get("api_endpoint", "http://localhost:11434"))
        config.setdefault("model", config.get("model", "llama3.2"))
        super().__init__(config)

    def provider_name(self) -> str:
        return "ollama"

    def provider_version(self) -> str:
        return "1.0.0"

    def _chat_endpoint(self) -> str:
        return "api/chat"

    def _completion_endpoint(self) -> str:
        return "api/generate"

    def _embeddings_endpoint(self) -> str:
        return "api/embeddings"

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "User-Agent": f"HunterX-AI/{self.provider_version()}",
        }

    def model_list(self) -> List[ModelInfo]:
        try:
            data = self._request("GET", "api/tags")
            models = data.get("models", [])
            return [
                ModelInfo(
                    id=m["name"],
                    name=m["name"],
                    provider="ollama",
                    capabilities=[
                        ModelCapability.CHAT, ModelCapability.STREAMING,
                        ModelCapability.SYSTEM_PROMPT, ModelCapability.COMPLETION,
                    ],
                    context_length=m.get("details", {}).get("context_length", 8192),
                )
                for m in models
            ]
        except Exception:
            return [
                ModelInfo(
                    id=self._config.get("model", "llama3.2"),
                    name=self._config.get("model", "llama3.2"),
                    provider="ollama",
                    capabilities=[
                        ModelCapability.CHAT, ModelCapability.STREAMING,
                        ModelCapability.SYSTEM_PROMPT, ModelCapability.COMPLETION,
                    ],
                    context_length=8192,
                    description="Ollama local LLM model",
                ),
            ]

    def _build_chat_payload(self, request: ChatRequest) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": request.model or self._config.get("model", "llama3.2"),
            "messages": [m.to_dict() for m in request.messages],
            "options": {
                "temperature": request.temperature,
                "top_p": request.top_p,
            },
        }
        if request.stream:
            payload["stream"] = True
        return payload

    def _parse_chat_response(self, data: Dict[str, Any], latency_ms: float) -> ChatResponse:
        message = data.get("message", {})
        content = message.get("content", "")
        usage_data = data.get("usage", {}) or data.get("metrics", {})
        total_duration = data.get("total_duration", 0) / 1e9

        return ChatResponse(
            content=content or "",
            model=data.get("model", ""),
            provider=self.provider_name(),
            finish_reason=FinishReason.STOP,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("prompt_eval_count", 0),
                completion_tokens=usage_data.get("eval_count", 0),
                total_tokens=(usage_data.get("prompt_eval_count", 0) + usage_data.get("eval_count", 0)),
            ),
            latency_ms=latency_ms or (total_duration * 1000),
            raw=data,
        )

    def stream(self, request: ChatRequest) -> Generator[StreamingChunk, None, None]:
        payload = self._build_chat_payload(request)
        payload["stream"] = True
        raw = self._request("POST", self._chat_endpoint(), json_data=payload, stream=True)
        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get("done"):
                yield StreamingChunk(content="", finish_reason=FinishReason.STOP)
                return
            message = data.get("message", {})
            content = message.get("content", "")
            if content:
                yield StreamingChunk(content=content)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        start = time.monotonic()
        payload = {
            "model": request.model or self._config.get("model", "llama3.2"),
            "prompt": request.prompt,
            "options": {
                "temperature": request.temperature,
                "top_p": request.top_p,
            },
            "stream": False,
        }
        data = self._request("POST", "api/generate", json_data=payload)
        latency = (time.monotonic() - start) * 1000
        usage_data = data.get("metrics", {})
        return CompletionResponse(
            content=data.get("response", ""),
            model=data.get("model", ""),
            provider=self.provider_name(),
            finish_reason=FinishReason.STOP,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("prompt_eval_count", 0),
                completion_tokens=usage_data.get("eval_count", 0),
                total_tokens=(usage_data.get("prompt_eval_count", 0) + usage_data.get("eval_count", 0)),
            ),
            latency_ms=latency,
        )

    def embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        start = time.monotonic()
        payload = {
            "model": request.model or self._config.get("model", "llama3.2"),
            "prompt": request.input[0] if request.input else "",
        }
        data = self._request("POST", "api/embeddings", json_data=payload)
        latency = (time.monotonic() - start) * 1000
        return EmbeddingResponse(
            embeddings=[data.get("embedding", [])],
            model=data.get("model", ""),
            provider=self.provider_name(),
            latency_ms=latency,
        )

    def tokenize(self, text: str) -> List[int]:
        try:
            payload = {"model": self._config.get("model", "llama3.2"), "prompt": text}
            data = self._request("POST", "api/tokenize", json_data=payload)
            return data.get("tokens", [])
        except Exception:
            return super().tokenize(text)

    def count_tokens(self, text: str) -> int:
        tokens = self.tokenize(text)
        return len(tokens) if tokens else super().count_tokens(text)

    def supports_embeddings(self) -> bool:
        return True

    def supports_streaming(self) -> bool:
        return True

    def supports_json_mode(self) -> bool:
        return False

    def supports_tools(self) -> bool:
        return False

    def supports_function_calling(self) -> bool:
        return False

    def supports_reasoning(self) -> bool:
        return False

    def supports_vision(self) -> bool:
        return True

    def supports_images(self) -> bool:
        return True

    def supports_system_prompt(self) -> bool:
        return True

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return 0.0
