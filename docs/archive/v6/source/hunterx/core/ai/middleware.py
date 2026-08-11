from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List

from ...utils.utils import logger
from .exceptions import RateLimitError, RetryHandler


class Middleware:
    def before(self, provider: str) -> None:
        ...

    def after(self, provider: str, response: Any) -> None:
        ...

    def on_error(self, provider: str, error: Exception) -> None:
        ...


class LoggingMiddleware(Middleware):
    def before(self, provider: str) -> None:
        logger.debug(f"Middleware: calling {provider}")

    def after(self, provider: str, response: Any) -> None:
        logger.debug(f"Middleware: {provider} completed")

    def on_error(self, provider: str, error: Exception) -> None:
        logger.warning(f"Middleware: {provider} error: {error}")


class RateLimitMiddleware(Middleware):
    def __init__(self, rpm: int = 60):
        self.rpm = rpm
        self._window_size = 60.0
        self._tokens: int = rpm
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    def before(self, provider: str) -> None:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.rpm, self._tokens + int(elapsed * (self.rpm / self._window_size)))
            self._last_refill = now

            if self._tokens <= 0:
                retry_after = self._window_size / max(1, self.rpm)
                raise RateLimitError(provider, retry_after=retry_after)

            self._tokens -= 1

    def after(self, provider: str, response: Any) -> None:
        pass


class SafetyMiddleware(Middleware):
    SENSITIVE_PATTERNS = [
        "api_key", "api-key", "apikey", "secret", "password", "token",
        "authorization", "x-api-key", "bearer", "jwt",
    ]

    def before(self, provider: str) -> None:
        pass

    def after(self, provider: str, response: Any) -> None:
        pass

    @staticmethod
    def sanitize(data: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(data, dict):
            return data
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            if any(p in key.lower() for p in SafetyMiddleware.SENSITIVE_PATTERNS):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = SafetyMiddleware.sanitize(value)
            else:
                sanitized[key] = value
        return sanitized


class RetryMiddleware(Middleware):
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self._handler = RetryHandler(max_retries=max_retries, base_delay=base_delay)

    def before(self, provider: str) -> None:
        pass

    def after(self, provider: str, response: Any) -> None:
        pass

    def execute(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return self._handler.execute(func, *args, **kwargs)


class MetricsMiddleware(Middleware):
    def __init__(self):
        self._start_times: Dict[str, float] = {}

    def before(self, provider: str) -> None:
        self._start_times[provider] = time.monotonic()

    def after(self, provider: str, response: Any) -> None:
        pass

    def on_error(self, provider: str, error: Exception) -> None:
        pass


class MiddlewarePipeline:
    def __init__(self):
        self._middleware: List[Middleware] = [
            LoggingMiddleware(),
            RateLimitMiddleware(),
            SafetyMiddleware(),
            MetricsMiddleware(),
        ]
        self._retry_middleware = RetryMiddleware()

    def add(self, middleware: Middleware) -> None:
        self._middleware.append(middleware)

    def remove(self, middleware_type: type) -> bool:
        for i, m in enumerate(self._middleware):
            if isinstance(m, middleware_type):
                self._middleware.pop(i)
                return True
        return False

    def execute(self, func: Callable[..., Any], provider: str) -> Any:
        for m in self._middleware:
            m.before(provider)

        try:
            result = self._retry_middleware.execute(func)
            for m in reversed(self._middleware):
                m.after(provider, result)
            return result
        except Exception as e:
            for m in reversed(self._middleware):
                m.on_error(provider, e)
            raise
