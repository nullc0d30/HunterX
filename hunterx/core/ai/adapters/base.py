from __future__ import annotations

import json
import time
from typing import Any, Dict, Generator, List, Optional

from ....utils.utils import logger
from ..exceptions import (
    AIError,
    AuthenticationError,
    CircuitBreaker,
    InvalidRequestError,
    ProviderUnavailableError,
    RateLimitError,
    RetryHandler,
    TimeoutError,
)
from ..models import (
    ChatRequest,
    ChatResponse,
    CompletionRequest,
    CompletionResponse,
    EmbeddingRequest,
    EmbeddingResponse,
    FinishReason,
    ProviderStatus,
    StreamingChunk,
    TokenUsage,
)
from ..provider import AIProvider


class BaseHTTPAdapter(AIProvider):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._api_key: str = self._config.get("api_key", "")
        self._api_endpoint: str = self._config.get("api_endpoint", "")
        self._organization: str = self._config.get("organization", "")
        self._timeout: float = float(self._config.get("timeout", 60.0))
        self._max_retries: int = int(self._config.get("max_retries", 3))
        self._session = None
        self._retry_handler = RetryHandler(
            max_retries=self._max_retries,
            base_delay=1.0,
            backoff_factor=2.0,
            retryable_exceptions=[RateLimitError, TimeoutError, ProviderUnavailableError],
        )
        self._circuit_breaker = CircuitBreaker(name=self.provider_name())

    def _get_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"HunterX-AI/{self.provider_version()}",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        if self._organization:
            headers["OpenAI-Organization"] = self._organization
        return headers

    def _request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        stream: bool = False,
    ) -> Any:
        import urllib.request
        import urllib.error

        url = f"{self._api_endpoint.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = self._get_headers()
        data = json.dumps(json_data).encode("utf-8") if json_data else None

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            resp = urllib.request.urlopen(req, timeout=self._timeout)
            resp_data = resp.read()
            resp_code = resp.status
        except urllib.error.HTTPError as e:
            resp_code = e.code
            resp_data = e.read()
            self._handle_http_error(resp_code, resp_data, endpoint)
            raise ProviderUnavailableError(self.provider_name())
        except urllib.error.URLError as e:
            raise TimeoutError(self.provider_name(), self._timeout) if "timed out" in str(e).lower() else ProviderUnavailableError(self.provider_name())

        if resp_code >= 400:
            self._handle_http_error(resp_code, resp_data, endpoint)

        if stream:
            return resp_data.decode("utf-8", errors="ignore")

        return json.loads(resp_data.decode("utf-8", errors="ignore"))

    def _handle_http_error(self, status_code: int, body: bytes, endpoint: str) -> None:
        error_text = body.decode("utf-8", errors="ignore")[:500]
        if status_code == 401:
            raise AuthenticationError(self.provider_name(), error_text)
        elif status_code == 429:
            raise RateLimitError(self.provider_name())
        elif status_code == 400:
            raise InvalidRequestError(error_text, self.provider_name())
        elif status_code >= 500:
            raise ProviderUnavailableError(self.provider_name())
        else:
            raise AIError(f"HTTP {status_code}: {error_text}", provider=self.provider_name(), status_code=status_code)

    def initialize(self) -> None:
        try:
            health = self.health()
            if health.available:
                self._initialized = True
        except Exception as e:
            logger.warning(f"{self.provider_name()}: initialization failed: {e}")
            self._initialized = False

    def shutdown(self) -> None:
        self._initialized = False

    def chat(self, request: ChatRequest) -> ChatResponse:
        return self._circuit_breaker.call(lambda: self._chat_internal(request))

    def _chat_internal(self, request: ChatRequest) -> ChatResponse:
        start = time.monotonic()
        payload = self._build_chat_payload(request)
        data = self._request("POST", self._chat_endpoint(), json_data=payload)
        latency = (time.monotonic() - start) * 1000
        return self._parse_chat_response(data, latency)

    def stream(self, request: ChatRequest) -> Generator[StreamingChunk, None, None]:
        payload = self._build_chat_payload(request)
        payload["stream"] = True
        raw = self._request("POST", self._chat_endpoint(), json_data=payload, stream=True)
        for chunk in self._parse_stream_chunks(raw):
            yield chunk

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        start = time.monotonic()
        payload = self._build_completion_payload(request)
        data = self._request("POST", self._completion_endpoint(), json_data=payload)
        latency = (time.monotonic() - start) * 1000
        return self._parse_completion_response(data, latency)

    def embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        start = time.monotonic()
        payload = self._build_embedding_payload(request)
        data = self._request("POST", self._embeddings_endpoint(), json_data=payload)
        latency = (time.monotonic() - start) * 1000
        return self._parse_embedding_response(data, latency)

    def tokenize(self, text: str) -> List[int]:
        return [ord(c) for c in text[:1000]]

    def count_tokens(self, text: str) -> int:
        return len(text) // 4 + 1

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        models = self.model_list()
        cost = 0.0
        for m in models:
            cost += (prompt_tokens * m.pricing_prompt + completion_tokens * m.pricing_completion)
        return cost / max(1, len(models))

    def health(self) -> ProviderStatus:
        try:
            start = time.monotonic()
            models = self.model_list()
            latency = (time.monotonic() - start) * 1000
            return ProviderStatus(
                provider=self.provider_name(),
                available=True,
                healthy=True,
                latency_ms=latency,
                model_count=len(models),
            )
        except Exception as e:
            return ProviderStatus(
                provider=self.provider_name(),
                available=False,
                healthy=False,
                error=str(e),
            )

    def supports_streaming(self) -> bool:
        return True

    def supports_tools(self) -> bool:
        return True

    def supports_images(self) -> bool:
        return False

    def supports_embeddings(self) -> bool:
        return False

    def supports_json_mode(self) -> bool:
        return True

    def supports_function_calling(self) -> bool:
        return True

    def supports_reasoning(self) -> bool:
        return False

    def supports_system_prompt(self) -> bool:
        return True

    def supports_vision(self) -> bool:
        return False

    def _chat_endpoint(self) -> str:
        return "v1/chat/completions"

    def _completion_endpoint(self) -> str:
        return "v1/completions"

    def _embeddings_endpoint(self) -> str:
        return "v1/embeddings"

    def _build_chat_payload(self, request: ChatRequest) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": request.model or self._config.get("model", ""),
            "messages": [m.to_dict() for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
        }
        if request.stop:
            payload["stop"] = request.stop
        if request.json_mode and self.supports_json_mode():
            payload["response_format"] = {"type": "json_object"}
        if request.tools:
            payload["tools"] = request.tools
        if request.seed is not None:
            payload["seed"] = request.seed
        if request.presence_penalty:
            payload["presence_penalty"] = request.presence_penalty
        if request.frequency_penalty:
            payload["frequency_penalty"] = request.frequency_penalty
        return payload

    def _build_completion_payload(self, request: CompletionRequest) -> Dict[str, Any]:
        return {
            "model": request.model or self._config.get("model", ""),
            "prompt": request.prompt,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stop": request.stop,
        }

    def _build_embedding_payload(self, request: EmbeddingRequest) -> Dict[str, Any]:
        return {
            "model": request.model or self._config.get("embedding_model", "text-embedding-ada-002"),
            "input": request.input,
        }

    def _parse_chat_response(self, data: Dict[str, Any], latency_ms: float) -> ChatResponse:
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "")
        finish = choice.get("finish_reason", "stop")
        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )
        return ChatResponse(
            content=content or "",
            model=data.get("model", ""),
            provider=self.provider_name(),
            finish_reason=self._parse_finish_reason(finish),
            usage=usage,
            tool_calls=message.get("tool_calls"),
            latency_ms=latency_ms,
            raw=data,
        )

    def _parse_completion_response(self, data: Dict[str, Any], latency_ms: float) -> CompletionResponse:
        choice = data.get("choices", [{}])[0]
        content = choice.get("text", "")
        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )
        return CompletionResponse(
            content=content or "",
            model=data.get("model", ""),
            provider=self.provider_name(),
            finish_reason=self._parse_finish_reason(choice.get("finish_reason", "stop")),
            usage=usage,
            latency_ms=latency_ms,
        )

    def _parse_embedding_response(self, data: Dict[str, Any], latency_ms: float) -> EmbeddingResponse:
        embeddings = [item["embedding"] for item in data.get("data", [])]
        usage_data = data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )
        return EmbeddingResponse(
            embeddings=embeddings,
            model=data.get("model", ""),
            provider=self.provider_name(),
            usage=usage,
            latency_ms=latency_ms,
        )

    def _parse_stream_chunks(self, raw: str) -> Generator[StreamingChunk, None, None]:
        for line in raw.split("\n"):
            line = line.strip()
            if not line or line.startswith(":"):
                continue
            if line.startswith("data: "):
                data_str = line[6:]
                if data_str == "[DONE]":
                    yield StreamingChunk(content="", finish_reason=FinishReason.STOP)
                    return
                try:
                    data = json.loads(data_str)
                    choice = data.get("choices", [{}])[0]
                    delta = choice.get("delta", {})
                    content = delta.get("content", "")
                    finish = choice.get("finish_reason")
                    if content or finish:
                        yield StreamingChunk(
                            content=content or "",
                            finish_reason=self._parse_finish_reason(finish) if finish else None,
                        )
                except json.JSONDecodeError:
                    continue

    def _parse_finish_reason(self, reason: Optional[str]) -> FinishReason:
        if not reason:
            return FinishReason.OTHER
        mapping = {
            "stop": FinishReason.STOP,
            "length": FinishReason.LENGTH,
            "content_filter": FinishReason.CONTENT_FILTER,
            "tool_calls": FinishReason.TOOL_CALLS,
        }
        return mapping.get(reason.lower(), FinishReason.OTHER)
