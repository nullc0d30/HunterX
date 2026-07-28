from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class ProviderMetrics:
    provider: str = ""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_cost_estimate: float = 0.0
    total_latency_ms: float = 0.0
    min_latency_ms: float = float("inf")
    max_latency_ms: float = 0.0
    streaming_count: int = 0
    streaming_total_duration_ms: float = 0.0
    errors: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_request_at: Optional[datetime] = None

    def record_request(
        self,
        duration_ms: float,
        success: bool,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost: float = 0.0,
        error: str = "",
    ) -> None:
        self.total_requests += 1
        self.total_latency_ms += duration_ms
        self.min_latency_ms = min(self.min_latency_ms, duration_ms)
        self.max_latency_ms = max(self.max_latency_ms, duration_ms)
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_cost_estimate += cost
        self.last_request_at = datetime.utcnow()

        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
            if error:
                self.errors[error] = self.errors.get(error, 0) + 1

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.successful_requests / max(1, self.total_requests)

    @property
    def avg_latency_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": round(self.success_rate, 3),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "min_latency_ms": round(self.min_latency_ms, 1) if self.min_latency_ms != float("inf") else 0,
            "max_latency_ms": round(self.max_latency_ms, 1),
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "total_cost_estimate": round(self.total_cost_estimate, 6),
            "streaming_count": self.streaming_count,
            "errors": dict(self.errors),
            "last_request_at": self.last_request_at.isoformat() if self.last_request_at else None,
        }


@dataclass
class ModelMetrics:
    model: str = ""
    provider: str = ""
    total_requests: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_latency_ms: float = 0.0

    def record(self, prompt_tokens: int, completion_tokens: int, latency_ms: float) -> None:
        self.total_requests += 1
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_latency_ms += latency_ms

    @property
    def avg_latency_ms(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "provider": self.provider,
            "total_requests": self.total_requests,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
            "avg_latency_ms": round(self.avg_latency_ms, 1),
        }


class AIMetricsCollector:
    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._lock = threading.RLock()
        self._provider_metrics: Dict[str, ProviderMetrics] = {}
        self._model_metrics: Dict[str, ModelMetrics] = {}
        self._start_time = time.time()

    def record_request(
        self,
        provider: str,
        model: str = "",
        duration_ms: float = 0.0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        success: bool = True,
        error: str = "",
    ) -> None:
        if not self._enabled:
            return

        with self._lock:
            if provider not in self._provider_metrics:
                self._provider_metrics[provider] = ProviderMetrics(provider=provider)
            self._provider_metrics[provider].record_request(
                duration_ms=duration_ms,
                success=success,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                error=error,
            )

            if model:
                model_key = f"{provider}:{model}"
                if model_key not in self._model_metrics:
                    self._model_metrics[model_key] = ModelMetrics(model=model, provider=provider)
                self._model_metrics[model_key].record(
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    latency_ms=duration_ms,
                )

    def record_streaming_duration(self, provider: str, duration_ms: float) -> None:
        if not self._enabled:
            return
        with self._lock:
            if provider not in self._provider_metrics:
                self._provider_metrics[provider] = ProviderMetrics(provider=provider)
            self._provider_metrics[provider].streaming_count += 1
            self._provider_metrics[provider].streaming_total_duration_ms += duration_ms

    def get_provider_metrics(self, provider: str) -> Optional[ProviderMetrics]:
        return self._provider_metrics.get(provider)

    def get_model_metrics(self, model: str, provider: str = "") -> Optional[ModelMetrics]:
        if provider:
            return self._model_metrics.get(f"{provider}:{model}")
        for key, metrics in self._model_metrics.items():
            if metrics.model == model:
                return metrics
        return None

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            uptime = time.time() - self._start_time
            total_requests = sum(m.total_requests for m in self._provider_metrics.values())
            total_success = sum(m.successful_requests for m in self._provider_metrics.values())
            total_failed = sum(m.failed_requests for m in self._provider_metrics.values())
            total_prompt = sum(m.total_prompt_tokens for m in self._provider_metrics.values())
            total_completion = sum(m.total_completion_tokens for m in self._provider_metrics.values())
            total_cost = sum(m.total_cost_estimate for m in self._provider_metrics.values())

            return {
                "uptime_seconds": round(uptime),
                "total_requests": total_requests,
                "successful_requests": total_success,
                "failed_requests": total_failed,
                "success_rate": round(total_success / max(1, total_requests), 3),
                "total_prompt_tokens": total_prompt,
                "total_completion_tokens": total_completion,
                "total_tokens": total_prompt + total_completion,
                "total_cost_estimate": round(total_cost, 6),
                "providers": {k: v.to_dict() for k, v in sorted(self._provider_metrics.items())},
                "models": {k: v.to_dict() for k, v in sorted(self._model_metrics.items())},
            }
