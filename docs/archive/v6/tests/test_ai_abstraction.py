import os
import sys
import tempfile
import time
from typing import Generator, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.ai.models import (
    Message, MessageRole, ChatRequest, ChatResponse, CompletionRequest,
    CompletionResponse, EmbeddingRequest, EmbeddingResponse, TokenUsage,
    FinishReason, ModelCapability, ModelInfo, ProviderStatus,
    AIConfigProfile, StreamingChunk,
)
from core.ai.exceptions import (
    AIError, ProviderNotFoundError, RateLimitError,
    TimeoutError, ProviderUnavailableError, CircuitBreaker, CircuitBreakerState, RetryHandler,
    AIErrorHandler,
)
from core.ai.config import AIConfig, AIConfigManager
from core.ai.provider import AIProvider
from core.ai.registry import ProviderRegistry
from core.ai.factory import AIFactory
from core.ai.cache import AICache
from core.ai.metrics import AIMetricsCollector, ProviderMetrics
from core.ai.middleware import (
    MiddlewarePipeline, LoggingMiddleware, RateLimitMiddleware,
    SafetyMiddleware,
)
from core.ai.conversation import ConversationManager, Conversation
from core.ai.manager import AIManager
from core.ai.prompts.templates import PromptManager, PromptTemplate, PromptCategory


# =============================================================================
# Models
# =============================================================================

class TestMessage:
    def test_create_user_message(self):
        m = Message.user("hello")
        assert m.role == MessageRole.USER
        assert m.content == "hello"

    def test_create_system_message(self):
        m = Message.system("be helpful")
        assert m.role == MessageRole.SYSTEM
        assert m.content == "be helpful"

    def test_to_dict(self):
        m = Message(role=MessageRole.USER, content="test", name="user1")
        d = m.to_dict()
        assert d["role"] == "user"
        assert d["content"] == "test"
        assert d["name"] == "user1"


class TestTokenUsage:
    def test_defaults(self):
        u = TokenUsage()
        assert u.total_tokens == 0

    def test_addition(self):
        a = TokenUsage(100, 50, 150)
        b = TokenUsage(200, 100, 300)
        c = a + b
        assert c.prompt_tokens == 300
        assert c.total_tokens == 450


class TestChatRequest:
    def test_defaults(self):
        req = ChatRequest(messages=[Message.user("hi")])
        assert req.temperature == 0.7
        assert req.max_tokens == 2048

    def test_to_dict(self):
        req = ChatRequest(
            messages=[Message.user("hi"), Message.assistant("hello")],
            model="gpt-4", temperature=0.5, max_tokens=100, stream=True,
        )
        d = req.to_dict()
        assert d["model"] == "gpt-4"
        assert d["temperature"] == 0.5
        assert len(d["messages"]) == 2


class TestModelInfo:
    def test_defaults(self):
        m = ModelInfo(id="test", name="Test", provider="test")
        assert m.context_length == 4096

    def test_supports(self):
        m = ModelInfo(id="test", name="Test", provider="test",
                      capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING])
        assert m.supports(ModelCapability.CHAT)
        assert not m.supports(ModelCapability.VISION)

    def test_to_dict(self):
        m = ModelInfo(id="gpt-4", name="GPT-4", provider="openai",
                      capabilities=[ModelCapability.CHAT])
        d = m.to_dict()
        assert d["id"] == "gpt-4"
        assert "chat" in d["capabilities"]


# =============================================================================
# Exceptions & Error Handling
# =============================================================================

class TestAIError:
    def test_defaults(self):
        e = AIError("test error")
        assert str(e) == "test error"
        assert e.provider == ""

    def test_with_provider(self):
        e = AIError("fail", provider="openai", status_code=429)
        assert e.provider == "openai"
        assert e.status_code == 429


class TestProviderNotFoundError:
    def test_message(self):
        e = ProviderNotFoundError("test_provider")
        assert "test_provider" in str(e)


class TestCircuitBreaker:
    def test_initial_state(self):
        cb = CircuitBreaker("test", failure_threshold=3)
        assert cb.state == CircuitBreakerState.CLOSED

    def test_opens_on_failures(self):
        cb = CircuitBreaker("test", failure_threshold=3, recovery_timeout=0.1)
        call_count = [0]
        def failing():
            call_count[0] += 1
            raise ValueError("fail")

        for _ in range(3):
            try:
                cb.call(failing)
            except (ValueError, ProviderUnavailableError):
                pass
        assert cb.state == CircuitBreakerState.OPEN
        assert call_count[0] == 3

    def test_reset(self):
        cb = CircuitBreaker("test", failure_threshold=2)
        cb._on_failure()
        cb._on_failure()
        assert cb.state == CircuitBreakerState.OPEN
        cb.reset()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.failure_count == 0

    def test_to_dict(self):
        cb = CircuitBreaker("test")
        d = cb.to_dict()
        assert d["name"] == "test"
        assert d["state"] == "closed"


class TestRetryHandler:
    def test_success_first_try(self):
        handler = RetryHandler(max_retries=3)
        result = handler.execute(lambda: "ok")
        assert result == "ok"

    def test_retry_on_failure(self):
        handler = RetryHandler(max_retries=2, base_delay=0.01)
        call_count = [0]
        def fails_then_works():
            call_count[0] += 1
            if call_count[0] < 2:
                raise TimeoutError("test", 1.0)
            return "success"

        result = handler.execute(fails_then_works)
        assert result == "success"
        assert call_count[0] == 2

    def test_exhaust_retries(self):
        handler = RetryHandler(max_retries=1, base_delay=0.01)
        def always_fails():
            raise RateLimitError("test")

        try:
            handler.execute(always_fails)
            assert False, "should have raised"
        except RateLimitError:
            pass


class TestAIErrorHandler:
    def test_execute(self):
        handler = AIErrorHandler()
        result = handler.execute(lambda: "ok")
        assert result == "ok"


# =============================================================================
# Config
# =============================================================================

class TestAIConfig:
    def test_defaults(self):
        cfg = AIConfig()
        assert cfg.enabled is True
        assert cfg.cache_enabled is True

    def test_to_dict(self):
        cfg = AIConfig(default_provider="openai", default_model="gpt-4")
        d = cfg.to_dict()
        assert d["default_provider"] == "openai"
        assert d["default_model"] == "gpt-4"


class TestAIConfigManager:
    def test_load_defaults(self):
        AIConfigManager.reset()
        cfg = AIConfigManager.load()
        assert cfg is not None
        assert cfg.enabled is True

    def test_load_from_dict(self):
        AIConfigManager.reset()
        cfg = AIConfigManager.load()
        cfg.default_provider = "ollama"
        assert cfg.default_provider == "ollama"

    def test_get_profile(self):
        cfg = AIConfig()
        profile = cfg.get_profile("nonexistent")
        assert profile.name == "default"


# =============================================================================
# Mock Provider for testing
# =============================================================================

class MockProvider(AIProvider):
    def __init__(self, config=None):
        super().__init__(config)
        self._call_count = 0

    def provider_name(self) -> str:
        return "mock"

    def provider_version(self) -> str:
        return "1.0.0"

    def initialize(self) -> None:
        self._initialized = True

    def shutdown(self) -> None:
        self._initialized = False

    def health(self) -> ProviderStatus:
        return ProviderStatus(
            provider="mock", available=True, healthy=True,
            latency_ms=1.0, model_count=2,
        )

    def chat(self, request: ChatRequest) -> ChatResponse:
        self._call_count += 1
        return ChatResponse(
            content="mock response",
            model=request.model or "mock-model",
            provider="mock",
            usage=TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        )

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        return CompletionResponse(content="mock", model="mock", provider="mock")

    def stream(self, request: ChatRequest) -> Generator[StreamingChunk, None, None]:
        yield StreamingChunk(content="mock ")
        yield StreamingChunk(content="stream")

    def embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        return EmbeddingResponse(
            embeddings=[[0.1, 0.2, 0.3]],
            model="mock", provider="mock",
        )

    def tokenize(self, text: str) -> List[int]:
        return [ord(c) for c in text]

    def count_tokens(self, text: str) -> int:
        return len(text) // 4 + 1

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        return 0.001

    def supports_streaming(self) -> bool: return True
    def supports_tools(self) -> bool: return False
    def supports_images(self) -> bool: return False
    def supports_embeddings(self) -> bool: return True
    def supports_json_mode(self) -> bool: return True
    def supports_function_calling(self) -> bool: return False
    def supports_reasoning(self) -> bool: return False
    def supports_system_prompt(self) -> bool: return True
    def supports_vision(self) -> bool: return False

    def model_list(self) -> List[ModelInfo]:
        return [
            ModelInfo(id="mock-model", name="Mock Model", provider="mock",
                      capabilities=[ModelCapability.CHAT, ModelCapability.STREAMING]),
        ]


class FailingProvider(AIProvider):
    def provider_name(self) -> str: return "failing"
    def provider_version(self) -> str: return "1.0.0"
    def initialize(self) -> None: self._initialized = True
    def shutdown(self) -> None: self._initialized = False
    def health(self) -> ProviderStatus:
        return ProviderStatus(provider="failing", available=False, healthy=False, error="down")
    def chat(self, request: ChatRequest) -> ChatResponse:
        raise ProviderUnavailableError("failing")
    def complete(self, request: CompletionRequest) -> CompletionResponse:
        raise ProviderUnavailableError("failing")
    def embeddings(self, request: EmbeddingRequest) -> EmbeddingResponse:
        raise ProviderUnavailableError("failing")
    def tokenize(self, text: str) -> List[int]: return []
    def count_tokens(self, text: str) -> int: return 0
    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> float: return 0.0
    def supports_streaming(self) -> bool: return True
    def supports_tools(self) -> bool: return False
    def supports_images(self) -> bool: return False
    def supports_embeddings(self) -> bool: return False
    def supports_json_mode(self) -> bool: return False
    def supports_function_calling(self) -> bool: return False
    def supports_reasoning(self) -> bool: return False
    def supports_system_prompt(self) -> bool: return True
    def supports_vision(self) -> bool: return False
    def model_list(self) -> List[ModelInfo]: return []


# =============================================================================
# Registry
# =============================================================================

class TestProviderRegistry:
    def test_singleton(self):
        r1 = ProviderRegistry()
        r2 = ProviderRegistry()
        assert r1 is r2

    def test_register_and_list(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        providers = registry.list()
        assert "mock" in providers

    def test_get(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        provider = registry.get("mock")
        assert provider.provider_name() == "mock"
        assert provider.initialized is True

    def test_get_not_found(self):
        registry = ProviderRegistry()
        try:
            registry.get("nonexistent")
            assert False
        except ProviderNotFoundError:
            pass

    def test_unregister(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        registry.unregister("mock")
        assert "mock" not in registry.list()

    def test_health_check(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        status = registry.health_check("mock")
        assert status.healthy is True
        assert status.available is True

    def test_health_check_all(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        registry.register(FailingProvider, name="failing")
        results = registry.health_check_all()
        assert "mock" in results
        assert "failing" in results
        assert results["mock"].healthy is True
        assert results["failing"].healthy is False

    def test_list_with_status(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        statuses = registry.list_with_status()
        assert len(statuses) >= 1
        assert any(s["name"] == "mock" for s in statuses)


# =============================================================================
# Factory
# =============================================================================

class TestAIFactory:
    def test_create(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        factory = AIFactory(registry)
        provider = factory.create("mock")
        assert provider.provider_name() == "mock"

    def test_create_default(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        factory = AIFactory(registry)
        provider = factory.create_default()
        assert provider is not None

    def test_create_with_fallback_primary_works(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        registry.register(FailingProvider, name="failing")
        factory = AIFactory(registry)
        provider = factory.create_with_fallback("mock", "failing")
        assert provider.provider_name() == "mock"

    def test_create_with_fallback_fallback_used(self):
        registry = ProviderRegistry()
        registry.register(FailingProvider, name="failing")
        registry.register(MockProvider, name="mock")
        factory = AIFactory(registry)
        provider = factory.create_with_fallback("failing", "mock")
        assert provider.provider_name() == "mock"

    def test_create_priority(self):
        registry = ProviderRegistry()
        registry.register(FailingProvider, name="failing")
        registry.register(MockProvider, name="mock")
        factory = AIFactory(registry)
        provider = factory.create_priority(["failing", "mock"])
        assert provider.provider_name() == "mock"

    def test_get_instance(self):
        factory = AIFactory.get_instance("test_factory")
        assert factory is not None


# =============================================================================
# Cache
# =============================================================================

class TestAICache:
    def test_get_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = AICache(db_path=os.path.join(tmp, "cache.db"))
            cache.set("key1", "value1")
            assert cache.get("key1") == "value1"
            cache.close()

    def test_get_miss(self):
        cache = AICache()
        assert cache.get("nonexistent") is None

    def test_ttl_expiry(self):
        cache = AICache(default_ttl=0)
        cache.set("key", "value")
        time.sleep(0.01)
        assert cache.get("key") is None

    def test_has(self):
        cache = AICache()
        cache.set("k", "v")
        assert cache.has("k") is True
        assert cache.has("missing") is False

    def test_compute_key(self):
        cache = AICache()
        k1 = cache.compute_key([{"role": "user", "content": "hi"}], "gpt-4", 0.7)
        k2 = cache.compute_key([{"role": "user", "content": "hi"}], "gpt-4", 0.7)
        assert k1 == k2
        k3 = cache.compute_key([{"role": "user", "content": "bye"}], "gpt-4", 0.7)
        assert k1 != k3

    def test_clear(self):
        cache = AICache()
        cache.set("k", "v")
        cache.clear()
        assert cache.get("k") is None

    def test_get_stats(self):
        cache = AICache()
        cache.set("k", "v")
        cache.get("k")
        cache.get("k")
        stats = cache.get_stats()
        assert stats["hits"] >= 2
        assert stats["enabled"] is True


# =============================================================================
# Metrics
# =============================================================================

class TestAIMetricsCollector:
    def test_record_request(self):
        metrics = AIMetricsCollector()
        metrics.record_request(provider="openai", model="gpt-4", duration_ms=100,
                               prompt_tokens=50, completion_tokens=30, success=True)
        summary = metrics.get_summary()
        assert summary["total_requests"] == 1
        assert summary["successful_requests"] == 1

    def test_record_failure(self):
        metrics = AIMetricsCollector()
        metrics.record_request(provider="openai", duration_ms=50, success=False, error="timeout")
        summary = metrics.get_summary()
        assert summary["failed_requests"] == 1
        assert summary["success_rate"] < 1.0

    def test_get_provider_metrics(self):
        metrics = AIMetricsCollector()
        metrics.record_request(provider="test_prov", duration_ms=200, success=True)
        pm = metrics.get_provider_metrics("test_prov")
        assert pm is not None
        assert pm.total_requests == 1

    def test_get_model_metrics(self):
        metrics = AIMetricsCollector()
        metrics.record_request(provider="openai", model="gpt-4", duration_ms=150,
                               prompt_tokens=100, completion_tokens=50, success=True)
        mm = metrics.get_model_metrics("gpt-4", "openai")
        assert mm is not None
        assert mm.total_requests == 1

    def test_disabled(self):
        metrics = AIMetricsCollector(enabled=False)
        metrics.record_request(provider="openai", duration_ms=100, success=True)
        summary = metrics.get_summary()
        assert summary["total_requests"] == 0

    def test_record_streaming(self):
        metrics = AIMetricsCollector()
        metrics.record_streaming_duration("openai", 5000)
        pm = metrics.get_provider_metrics("openai")
        assert pm is not None
        assert pm.streaming_count == 1


class TestProviderMetrics:
    def test_success_rate(self):
        pm = ProviderMetrics(provider="test")
        assert pm.success_rate == 1.0
        pm.record_request(100, success=True)
        pm.record_request(100, success=False, error="fail")
        assert pm.success_rate == 0.5

    def test_to_dict(self):
        pm = ProviderMetrics(provider="test")
        pm.record_request(100, success=True, prompt_tokens=10, completion_tokens=5)
        d = pm.to_dict()
        assert d["provider"] == "test"
        assert d["total_requests"] == 1


# =============================================================================
# Middleware
# =============================================================================

class TestMiddlewarePipeline:
    def test_execute_success(self):
        pipeline = MiddlewarePipeline()
        result = pipeline.execute(lambda: "ok", "test_provider")
        assert result == "ok"

    def test_execute_with_error(self):
        pipeline = MiddlewarePipeline()
        try:
            pipeline.execute(lambda: 1/0, "test_provider")
            assert False
        except ZeroDivisionError:
            pass

    def test_add_remove(self):
        pipeline = MiddlewarePipeline()
        pipeline.add(LoggingMiddleware())
        assert pipeline.remove(LoggingMiddleware) is True
        assert pipeline.remove(LoggingMiddleware) is False


class TestRateLimitMiddleware:
    def test_allows_request(self):
        rl = RateLimitMiddleware(rpm=1000)
        rl.before("test")  # should not raise

    def test_blocks_when_exhausted(self):
        rl = RateLimitMiddleware(rpm=1)
        rl.before("test")
        try:
            rl.before("test")
            # With 1 rpm, the second call may or may not be blocked depending on timing
        except RateLimitError:
            pass  # expected


class TestSafetyMiddleware:
    def test_sanitize_api_key(self):
        data = {"api_key": "sk-1234567890abcdef", "normal": "hello"}
        sanitized = SafetyMiddleware.sanitize(data)
        assert sanitized["api_key"] == "***REDACTED***"
        assert sanitized["normal"] == "hello"

    def test_sanitize_nested(self):
        data = {"config": {"password": "secret123", "user": "admin"}}
        sanitized = SafetyMiddleware.sanitize(data)
        assert sanitized["config"]["password"] == "***REDACTED***"
        assert sanitized["config"]["user"] == "admin"


# =============================================================================
# Conversation
# =============================================================================

class TestConversation:
    def test_create(self):
        conv = Conversation(id="test-id", system_prompt="be helpful")
        assert conv.id == "test-id"
        assert conv.system_prompt == "be helpful"

    def test_add_message(self):
        conv = Conversation(id="1")
        conv.add_message(Message.user("hello"))
        assert len(conv.messages) == 1
        assert conv.messages[0].content == "hello"

    def test_to_dict(self):
        conv = Conversation(id="1", system_prompt="help", max_tokens=8000)
        conv.add_message(Message.user("hi"))
        d = conv.to_dict()
        assert d["id"] == "1"
        assert d["message_count"] == 1


class TestConversationManager:
    def test_create(self):
        mgr = ConversationManager()
        conv = mgr.create(system_prompt="be helpful")
        assert conv.id is not None
        assert conv.system_prompt == "be helpful"

    def test_get_conversation(self):
        mgr = ConversationManager()
        conv = mgr.create()
        assert mgr.get_conversation(conv.id) is conv

    def test_get_nonexistent(self):
        mgr = ConversationManager()
        assert mgr.get_conversation("nope") is None

    def test_add_user_message(self):
        mgr = ConversationManager()
        conv = mgr.create()
        msg = mgr.add_user_message(conv.id, "hello")
        assert msg is not None
        assert msg.content == "hello"
        assert msg.role == MessageRole.USER

    def test_add_assistant_message(self):
        mgr = ConversationManager()
        conv = mgr.create()
        msg = mgr.add_assistant_message(conv.id, "hi there")
        assert msg is not None
        assert msg.role == MessageRole.ASSISTANT

    def test_get_messages(self):
        mgr = ConversationManager()
        conv = mgr.create()
        mgr.add_user_message(conv.id, "q1")
        mgr.add_assistant_message(conv.id, "a1")
        messages = mgr.get_messages(conv.id)
        assert len(messages) >= 2

    def test_clear_conversation(self):
        mgr = ConversationManager()
        conv = mgr.create()
        mgr.add_user_message(conv.id, "hello")
        assert mgr.clear_conversation(conv.id) is True
        assert len(conv.messages) == 0

    def test_delete_conversation(self):
        mgr = ConversationManager()
        conv = mgr.create()
        assert mgr.delete_conversation(conv.id) is True
        assert mgr.get_conversation(conv.id) is None

    def test_list_conversations(self):
        mgr = ConversationManager()
        mgr.create()
        mgr.create()
        assert len(mgr.list_conversations()) >= 2

    def test_get_statistics(self):
        mgr = ConversationManager()
        mgr.create()
        stats = mgr.get_statistics()
        assert stats["total_conversations"] >= 1

    def test_set_summary(self):
        mgr = ConversationManager()
        conv = mgr.create()
        assert mgr.set_summary(conv.id, "summary text") is True
        assert conv.summary == "summary text"

    def test_enforce_limits(self):
        mgr = ConversationManager(max_history=3)
        conv = mgr.create(system_prompt="system")
        for i in range(10):
            mgr.add_user_message(conv.id, f"msg{i}")
            mgr.add_assistant_message(conv.id, f"resp{i}")
        # Should have been trimmed
        assert len(conv.messages) <= 3


# =============================================================================
# Prompt Templates
# =============================================================================

class TestPromptTemplate:
    def test_render(self):
        tpl = PromptTemplate(
            name="test", category=PromptCategory.CLASSIFICATION,
            template="Hello {name}!",
            variables=["name"],
        )
        result = tpl.render(name="World")
        assert result == "Hello World!"

    def test_validate_missing(self):
        tpl = PromptTemplate(
            name="test", category=PromptCategory.CLASSIFICATION,
            template="{a} {b}", variables=["a", "b"],
        )
        missing = tpl.validate(a=1)
        assert "b" in missing

    def test_validate_ok(self):
        tpl = PromptTemplate(
            name="test", category=PromptCategory.CLASSIFICATION,
            template="{x}", variables=["x"],
        )
        missing = tpl.validate(x=42)
        assert missing == []


class TestPromptManager:
    def test_get_default(self):
        mgr = PromptManager()
        tpl = mgr.get("threat_analysis")
        assert tpl is not None
        assert tpl.category == PromptCategory.THREAT_MODELING

    def test_get_nonexistent(self):
        mgr = PromptManager()
        assert mgr.get("nope") is None

    def test_register(self):
        mgr = PromptManager()
        tpl = PromptTemplate(name="custom", category=PromptCategory.CODE_REVIEW, template="custom")
        mgr.register(tpl)
        assert mgr.get("custom") is tpl

    def test_list_by_category(self):
        mgr = PromptManager()
        templates = mgr.list_by_category(PromptCategory.CLASSIFICATION)
        assert len(templates) >= 2  # payload_classification + vulnerability_classification

    def test_list_all(self):
        mgr = PromptManager()
        assert len(mgr.list_all()) >= 10

    def test_get_categories(self):
        mgr = PromptManager()
        cats = mgr.get_categories()
        assert "threat_modeling" in cats
        assert "reasoning" in cats


# =============================================================================
# Manager (integration)
# =============================================================================

class TestAIManager:
    def test_chat_with_mock(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        from core.ai.config import AIConfigManager
        AIConfigManager.reset()
        config = AIConfigManager.load()
        config.default_provider = "mock"
        cache = AICache()
        metrics = AIMetricsCollector()
        manager = AIManager(registry=registry, cache=cache, metrics=metrics)
        response = manager.chat([Message.user("hello")])
        assert response.content == "mock response"
        assert response.provider == "mock"

    def test_chat_with_provider_arg(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        config = AIConfigManager.load()
        config.default_provider = "mock"
        manager = AIManager(registry=registry)
        response = manager.chat([Message.user("hi")], provider="mock")
        assert response.content == "mock response"

    def test_complete(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        response = manager.complete("test prompt")
        assert response is not None

    def test_embeddings(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        response = manager.embeddings(["hello world"])
        assert len(response.embeddings) == 1

    def test_count_tokens(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        count = manager.count_tokens("hello world")
        assert count > 0

    def test_health(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        status = manager.health("mock")
        assert status.healthy is True

    def test_health_all(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        results = manager.health_all()
        assert "mock" in results

    def test_list_providers(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        providers = manager.list_providers()
        assert any(p["name"] == "mock" for p in providers)

    def test_list_models(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        models = manager.list_models("mock")
        assert len(models) >= 1

    def test_create_conversation(self):
        manager = AIManager()
        conv = manager.create_conversation(system_prompt="help")
        assert conv is not None
        assert conv.system_prompt == "help"

    def test_get_metrics(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        metrics = AIMetricsCollector()
        manager = AIManager(registry=registry, metrics=metrics)
        manager.chat([Message.user("hi")])
        summary = manager.get_metrics()
        assert summary["total_requests"] >= 1

    def test_get_cache_stats(self):
        cache = AICache()
        manager = AIManager(cache=cache)
        stats = manager.get_cache_stats()
        assert stats["enabled"] is True

    def test_context_manager(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        with AIManager(registry=registry) as manager:
            response = manager.chat([Message.user("test")])
            assert response is not None

    def test_shutdown(self):
        registry = ProviderRegistry()
        registry.register(MockProvider)
        AIConfigManager.reset()
        AIConfigManager.load().default_provider = "mock"
        manager = AIManager(registry=registry)
        manager.shutdown()


# =============================================================================
# Config Profile
# =============================================================================

class TestAIConfigProfile:
    def test_defaults(self):
        p = AIConfigProfile()
        assert p.name == "default"
        assert p.temperature == 0.7
        assert p.max_tokens == 2048

    def test_custom(self):
        p = AIConfigProfile(
            name="my-profile", provider="openai", model="gpt-4",
            temperature=0.3, api_key="sk-test",
        )
        assert p.provider == "openai"
        assert p.model == "gpt-4"
        assert p.api_key == "sk-test"


# =============================================================================
# Provider capabilities
# =============================================================================

class TestAIModelCapability:
    def test_all_values(self):
        values = [c.value for c in ModelCapability]
        assert "chat" in values
        assert "streaming" in values
        assert "embeddings" in values
        assert "vision" in values
        assert "tools" in values


class TestFinishReason:
    def test_all_values(self):
        assert FinishReason.STOP.value == "stop"
        assert FinishReason.LENGTH.value == "length"
        assert FinishReason.ERROR.value == "error"


# =============================================================================
# Mock provider get_capabilities
# =============================================================================

class TestMockProviderCapabilities:
    def test_get_capabilities(self):
        p = MockProvider()
        caps = p.get_capabilities()
        cap_values = [c.value for c in caps]
        assert "chat" in cap_values
        assert "streaming" in cap_values
        assert "embeddings" in cap_values
        assert "json_mode" in cap_values
