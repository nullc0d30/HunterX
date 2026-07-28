from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class MessageRole(str, Enum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class FinishReason(str, Enum):
    STOP = "stop"
    LENGTH = "length"
    CONTENT_FILTER = "content_filter"
    TOOL_CALLS = "tool_calls"
    ERROR = "error"
    OTHER = "other"


class ModelCapability(str, Enum):
    CHAT = "chat"
    COMPLETION = "completion"
    STREAMING = "streaming"
    TOOLS = "tools"
    IMAGES = "images"
    EMBEDDINGS = "embeddings"
    JSON_MODE = "json_mode"
    FUNCTION_CALLING = "function_calling"
    REASONING = "reasoning"
    SYSTEM_PROMPT = "system_prompt"
    VISION = "vision"


@dataclass
class Message:
    role: MessageRole
    content: str
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"role": self.role.value, "content": self.content}
        if self.name:
            d["name"] = self.name
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        return d

    @classmethod
    def system(cls, content: str) -> Message:
        return cls(role=MessageRole.SYSTEM, content=content)

    @classmethod
    def user(cls, content: str) -> Message:
        return cls(role=MessageRole.USER, content=content)

    @classmethod
    def assistant(cls, content: str) -> Message:
        return cls(role=MessageRole.ASSISTANT, content=content)


@dataclass
class ChatRequest:
    messages: List[Message]
    model: str = ""
    provider: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.95
    stop: Optional[List[str]] = None
    stream: bool = False
    json_mode: bool = False
    tools: Optional[List[Dict[str, Any]]] = None
    presence_penalty: float = 0.0
    frequency_penalty: float = 0.0
    seed: Optional[int] = None
    user: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "messages": [m.to_dict() for m in self.messages],
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "stop": self.stop,
            "stream": self.stream,
            "json_mode": self.json_mode,
            "tools": self.tools,
            "presence_penalty": self.presence_penalty,
            "frequency_penalty": self.frequency_penalty,
            "seed": self.seed,
        }


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __add__(self, other: TokenUsage) -> TokenUsage:
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


@dataclass
class ChatResponse:
    content: str
    model: str
    provider: str
    finish_reason: FinishReason = FinishReason.STOP
    usage: Optional[TokenUsage] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    latency_ms: float = 0.0
    cached: bool = False
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider,
            "finish_reason": self.finish_reason.value,
            "usage": {"prompt_tokens": self.usage.prompt_tokens, "completion_tokens": self.usage.completion_tokens, "total_tokens": self.usage.total_tokens} if self.usage else None,
            "latency_ms": self.latency_ms,
            "cached": self.cached,
        }


@dataclass
class CompletionRequest:
    prompt: str
    model: str = ""
    provider: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 0.95
    stop: Optional[List[str]] = None
    stream: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt": self.prompt,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "stop": self.stop,
            "stream": self.stream,
        }


@dataclass
class CompletionResponse:
    content: str
    model: str
    provider: str
    finish_reason: FinishReason = FinishReason.STOP
    usage: Optional[TokenUsage] = None
    latency_ms: float = 0.0


@dataclass
class EmbeddingRequest:
    input: List[str]
    model: str = ""


@dataclass
class EmbeddingResponse:
    embeddings: List[List[float]]
    model: str
    provider: str
    usage: Optional[TokenUsage] = None
    latency_ms: float = 0.0


@dataclass
class StreamingChunk:
    content: str
    finish_reason: Optional[FinishReason] = None
    usage: Optional[TokenUsage] = None


@dataclass
class ModelInfo:
    id: str
    name: str
    provider: str
    capabilities: List[ModelCapability] = field(default_factory=list)
    context_length: int = 4096
    pricing_prompt: float = 0.0
    pricing_completion: float = 0.0
    description: str = ""

    def supports(self, capability: ModelCapability) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "capabilities": [c.value for c in self.capabilities],
            "context_length": self.context_length,
            "pricing_prompt": self.pricing_prompt,
            "pricing_completion": self.pricing_completion,
            "description": self.description,
        }


@dataclass
class ProviderStatus:
    provider: str
    available: bool
    healthy: bool
    latency_ms: float = 0.0
    model_count: int = 0
    error: Optional[str] = None
    last_check: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "available": self.available,
            "healthy": self.healthy,
            "latency_ms": self.latency_ms,
            "model_count": self.model_count,
            "error": self.error,
            "last_check": self.last_check.isoformat() if self.last_check else None,
        }


@dataclass
class AIConfigProfile:
    name: str = "default"
    provider: str = ""
    model: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    api_key: str = ""
    api_endpoint: str = ""
    organization: str = ""
    fallback_providers: List[str] = field(default_factory=list)
    timeout: float = 60.0
    max_retries: int = 3
    cache_ttl: int = 3600
    enable_cache: bool = True
    enable_metrics: bool = True
    enable_streaming: bool = True
    rate_limit_rpm: int = 60
    extra: Dict[str, Any] = field(default_factory=dict)
