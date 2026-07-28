from __future__ import annotations

import time
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar

from ..utils import logger

F = TypeVar("F", bound=Callable[..., Any])


class AIError(Exception):
    def __init__(self, message: str, provider: str = "", model: str = "", status_code: int = 0):
        self.provider = provider
        self.model = model
        self.status_code = status_code
        self.timestamp = datetime.utcnow()
        super().__init__(message)


class ProviderNotFoundError(AIError):
    def __init__(self, provider: str):
        super().__init__(f"AI provider not found: {provider}", provider=provider)


class ModelNotFoundError(AIError):
    def __init__(self, model: str, provider: str = ""):
        super().__init__(f"Model not found: {model}", provider=provider, model=model)


class AuthenticationError(AIError):
    def __init__(self, provider: str, message: str = "Authentication failed"):
        super().__init__(message, provider=provider, status_code=401)


class RateLimitError(AIError):
    def __init__(self, provider: str, retry_after: float = 0.0):
        self.retry_after = retry_after
        super().__init__(f"Rate limited by {provider}", provider=provider, status_code=429)


class TimeoutError(AIError):
    def __init__(self, provider: str, timeout: float):
        self.timeout = timeout
        super().__init__(f"Provider {provider} timed out after {timeout}s", provider=provider)


class ProviderUnavailableError(AIError):
    def __init__(self, provider: str):
        super().__init__(f"Provider {provider} is unavailable", provider=provider)


class InvalidRequestError(AIError):
    def __init__(self, message: str, provider: str = ""):
        super().__init__(message, provider=provider, status_code=400)


class ContextLengthExceededError(AIError):
    def __init__(self, provider: str, context_length: int, required: int):
        self.context_length = context_length
        self.required = required
        super().__init__(
            f"Context length exceeded: {required} > {context_length}",
            provider=provider,
        )


class ConfigurationError(AIError):
    def __init__(self, message: str):
        super().__init__(message)


class CircuitBreakerState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_retries: int = 3,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_retries = half_open_max_retries
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.half_open_attempts = 0

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self.state == CircuitBreakerState.OPEN:
            if self.last_failure_time and (time.monotonic() - self.last_failure_time) >= self.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                self.half_open_attempts = 0
            else:
                raise ProviderUnavailableError(self.name)

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.half_open_attempts += 1
            if self.half_open_attempts >= self.half_open_max_retries:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.half_open_attempts = 0
        else:
            self.failure_count = 0

    def _on_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN

    def reset(self) -> None:
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.half_open_attempts = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "last_failure_time": self.last_failure_time,
        }


class RetryHandler:
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        retryable_exceptions: Optional[List[type]] = None,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.retryable_exceptions = retryable_exceptions or [
            RateLimitError,
            TimeoutError,
            ProviderUnavailableError,
        ]

    def execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        last_exception: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except tuple(self.retryable_exceptions) as e:
                last_exception = e
                if attempt < self.max_retries:
                    delay = min(self.base_delay * (self.backoff_factor ** attempt), self.max_delay)
                    if isinstance(e, RateLimitError) and e.retry_after > 0:
                        delay = max(delay, e.retry_after)
                    logger.debug(f"Retry {attempt + 1}/{self.max_retries} after {delay:.1f}s: {e}")
                    time.sleep(delay)
                else:
                    logger.warning(f"All retries exhausted: {e}")
            except Exception:
                raise

        if last_exception:
            raise last_exception
        return None


class AIErrorHandler:
    def __init__(self, circuit_breaker: Optional[CircuitBreaker] = None, retry_handler: Optional[RetryHandler] = None):
        self.circuit_breaker = circuit_breaker
        self.retry_handler = retry_handler or RetryHandler()

    def execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self.circuit_breaker:
            return self.circuit_breaker.call(lambda: self.retry_handler.execute(func, *args, **kwargs))
        return self.retry_handler.execute(func, *args, **kwargs)
