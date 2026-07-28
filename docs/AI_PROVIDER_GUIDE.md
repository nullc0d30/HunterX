---
layout: default
title: AI Provider Abstraction Layer — HunterX v6.0.0
description: Modular AI provider abstraction layer for HunterX. Integrate OpenAI, Ollama, and other backends with caching and metrics.
permalink: /ai-provider-guide/
---

# AI Provider Abstraction Layer

HunterX v6.0.0 introduces a fully modular, plugin-based AI provider abstraction layer under `core/ai/`. This layer decouples the application from any single AI provider, enabling seamless integration of multiple backends (OpenAI, Ollama, etc.) with caching, metrics, middleware, and conversation management built in.

---

## Architecture

```
User/Agency
    |
    v
AIManager (facade)
    |
    v
AICache (SHA256 + TTL + LRU)
    |
    v
MiddlewarePipeline (Logging -> RateLimit -> Safety)
    |
    v
ProviderRegistry (routes to correct provider)
    |
    v
AIProvider (abstract)
    |
    +-- OllamaProvider
    +-- OpenAIProvider
    +-- (custom providers via plugin)
```

---

## Module Reference

### `manager.py` — AIManager

Singleton facade providing the main interface for all AI operations. Delegates to the appropriate provider via `ProviderRegistry`.

**Methods:** `chat`, `complete`, `embed`, `stream`, `list_models`, `get_metrics`, `get_cache_stats`, `clear_cache`.

### `provider.py` — AIProvider

Abstract base class that all providers must implement.

**Abstract methods (10):** `initialize`, `chat`, `complete`, `embed`, `stream`, `health`, `list_models`, `get_capabilities`, `to_dict`, `shutdown`.

### `registry.py` — ProviderRegistry

Singleton registry for provider instances.

**Methods:** `register`, `unregister`, `discover`, `list_with_status`, `health_check`, `health_check_all`, `get`, `get_all`.

Supports automatic discovery of provider classes.

### `factory.py` — AIFactory

Factory for creating provider instances with fallback support.

**Methods:** `create`, `create_with_fallback` (primary + fallback providers), `create_priority` (try providers in priority order), `register_provider_class`.

### `cache.py` — AICache

Response cache for AI operations. Uses SHA256 hashing of request parameters as cache key. TTL-based expiry. LRU eviction when cache is full. Tracks hit/miss statistics.

### `metrics.py` — AIMetricsCollector

Per-provider metrics collection. Tracks total requests, tokens (prompt/completion), latency (min/max/avg), error rates, and cost estimates. Provides per-provider rollups and overall system summary.

### `middleware.py` — Middleware Pipeline

Chain-of-responsibility pattern for pre/post processing of AI requests.

**Built-in middleware:**
- `LoggingMiddleware` — Request/response logging
- `RateLimitMiddleware` — Per-provider rate limiting
- `SafetyMiddleware` — Content filtering and policy enforcement

Custom middleware can be added by extending `BaseMiddleware`.

### `conversation.py` — Conversation & ConversationManager

Multi-turn conversation management. Each conversation tracks messages, token count, and metadata. Supports summarization for long conversations. Enforces token limits with automatic truncation.

### `config.py` — AIConfig & AIConfigManager

Configuration management for AI providers. YAML/ENV/CLI override chain. Supports named profiles with per-profile provider/model/temperature/max_tokens settings.

### `models.py` — Data Models

15+ data models including: `ChatRequest`, `ChatResponse`, `CompletionRequest`, `CompletionResponse`, `EmbeddingRequest`, `EmbeddingResponse`, `Message`, `MessageRole`, `ModelInfo`, `ModelCapability`, `ProviderStatus`, `StreamingChunk`, `TokenUsage`.

### `exceptions.py` — Error Handling

Complete exception hierarchy: `AIError`, `ProviderNotFoundError`, `AuthenticationError`, `RateLimitError`, `TimeoutError`, `ProviderUnavailableError`, `InvalidRequestError`, `ConfigurationError`.

Includes `CircuitBreaker` (with OPEN/HALF_OPEN/CLOSED states) and `RetryHandler` (configurable retries, backoff, max delay).

### `adapters/base.py` — BaseHTTPAdapter

Abstract HTTP adapter for REST-based AI providers. Handles common HTTP transport concerns.

### `providers/ollama.py` — OllamaProvider

Full Ollama integration: chat, complete, embed, streaming, health checks, model listing. Connects to local Ollama instance at configurable endpoint.

### `providers/openai.py` — OpenAIProvider

Full OpenAI integration: chat, complete, embed, streaming, health checks, model listing. Uses API key authentication.

### `prompts/` — Prompt Management

`PromptManager`, `PromptTemplate`, `PromptCategory` for managing prompt templates. Supports 10 categories with parameter substitution.

---

## Key Design Principles

- **Strict dependency inversion** — AI code depends on abstractions (`AIProvider`), not concrete implementations
- **Plugin-based discovery** — New providers can be added without modifying core
- **Caching** — All AI responses cached with configurable TTL (SHA256 key)
- **Middleware pipeline** — Logging, rate limiting, safety checks in chain-of-responsibility pattern
- **Metrics** — Per-provider latency, token usage, error rates, cost estimation
- **Conversation management** — Multi-turn with token limits and automatic summarization
- **Safety middleware** — Content filtering and policy enforcement before/after provider execution

---

## CLI

```bash
hunterx ai providers --json
hunterx ai health --provider openai
hunterx ai config --json
hunterx ai cache --json
hunterx ai metrics --json
hunterx ai test --provider ollama --model llama3.2 --prompt "Say hello"
hunterx ai models --provider openai --json
```

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/ai/providers` | List registered providers |
| GET | `/ai/health?provider=` | Provider health check |
| GET | `/ai/models?provider=` | List available models |
| GET | `/ai/metrics` | AI metrics and statistics |
| GET | `/ai/cache` | AI cache statistics |
| POST | `/ai/chat` | Chat completion |

### Chat Request Example

```json
POST /ai/chat
{
  "messages": [
    {"role": "system", "content": "You are a security analysis assistant."},
    {"role": "user", "content": "Analyze this HTTP response for vulnerabilities."}
  ],
  "model": "gpt-4",
  "provider": "openai",
  "temperature": 0.3,
  "max_tokens": 2048,
  "json_mode": true
}
```

### Chat Response Example

```json
{
  "content": "{\"vulnerabilities\": [...]}",
  "model": "gpt-4",
  "provider": "openai",
  "usage": {"prompt_tokens": 150, "completion_tokens": 300, "total_tokens": 450},
  "latency_ms": 2340
}
```

---

## Adding a New Provider

```python
from core.ai.provider import AIProvider
from core.ai.factory import AIFactory
from core.ai.registry import ProviderRegistry
from core.ai.models import ProviderStatus, ChatRequest, ChatResponse

class MyProvider(AIProvider):
    @property
    def name(self) -> str:
        return "my_provider"

    def initialize(self) -> None:
        # Set up API client, authentication, etc.
        pass

    def chat(self, request: ChatRequest) -> ChatResponse:
        # Implement chat completion
        return ChatResponse(content="...", model="my-model")

    def health(self) -> ProviderStatus:
        return ProviderStatus(provider=self.name, healthy=True)

    def list_models(self) -> list:
        return [{"id": "my-model", "capabilities": ["chat"]}]

# Register the provider
AIFactory.register_provider_class("my_provider", MyProvider)
ProviderRegistry().register(MyProvider())
```

---

## Configuration

Configured via `hunterx.yaml`, environment variables (`HX_AI_*`), or CLI flags:

```yaml
ai:
  enabled: true
  default_provider: ollama
  default_model: llama3.2
  cache_enabled: true
  metrics_enabled: true
  enable_streaming: false
  enable_fallback: true
  max_retries: 3
  endpoint: http://localhost:11434
  profiles:
    fast:
      provider: ollama
      model: llama3.2
      temperature: 0.7
      max_tokens: 1024
    deep:
      provider: openai
      model: gpt-4
      temperature: 0.3
      max_tokens: 4096
```
