# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process signature detector adapter.

The binary-free technology fingerprinting path. The adapter fetches the target
through an injectable ``FetchFn`` seam, runs the
:class:`~hunterx.domain.technology.detector.SignatureDetector` over the
collected evidence and emits canonical technology observations — the fallback
detector that requires no external tool (like tcp-connect and dnspython in
earlier capabilities).

Unlike binary adapters this adapter has no CLI; ``run`` collects evidence
in-process so unit tests never touch the network:
``SignatureAdapter(fetch=fake_fetch, detector=SignatureDetector())``.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import CachePort
from hunterx.domain.technology.detector import HttpEvidence, SignatureDetector
from hunterx.domain.technology.models import TechnologyObservation
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.tech.base import TechToolAdapter
from hunterx.tools.tech.httpclient import FetchFn, HttpFetcher

_VERSION = "1.0.0"

#: Cache key prefix for fetched HTTP evidence (URL-scoped, TTL-bounded).
_FETCH_CACHE_PREFIX = "fingerprint:http:"
#: Default TTL for cached fetch evidence in seconds.
_DEFAULT_CACHE_TTL = 60


@dataclass(frozen=True, slots=True)
class _FetchOutcome:
    """The outcome of one fetch attempt."""

    evidence: HttpEvidence
    error: str = ""


class SignatureAdapter(TechToolAdapter):
    """SDK adapter performing in-process signature-based technology detection.

    The adapter exposes a ``descriptor`` for registration and an execution
    lifecycle so it participates in the standard pipeline, but ``run`` collects
    an HTTP evidence bundle through the injectable fetch seam rather than a
    subprocess invocation.
    """

    descriptor = ToolDescriptor(
        name="signature",
        version=_VERSION,
        description="In-process signature-based technology detection over HTTP evidence.",
        entrypoint="hunterx.tools.tech.signature:SignatureAdapter",
        targets=("url", "host", "domain", "ip"),
        capabilities=("technology-fingerprinting",),
        permissions=("network",),
        parameters={
            "scheme": {
                "type": "string",
                "description": "Preferred scheme (https or http) for the fetch.",
            },
            "fallback": {
                "type": "boolean",
                "description": "Fall back to the alternate scheme when the preferred one yields no content.",
            },
            "timeout": {
                "type": "number",
                "description": "Per-fetch timeout in seconds.",
            },
        },
    )

    def __init__(
        self,
        fetch: FetchFn | None = None,
        detector: SignatureDetector | None = None,
        cache: CachePort | None = None,
        cache_ttl_s: int = _DEFAULT_CACHE_TTL,
    ) -> None:
        super().__init__()
        self._fetch = fetch or HttpFetcher().fetch
        self._detector = detector or SignatureDetector()
        self._cache = cache
        self._cache_ttl_s = cache_ttl_s

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """No CLI; returns an empty command line for the descriptor contract."""
        return []

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Fetch the target, detect technologies and emit observations."""
        url = _build_url(context.target, _scheme(context))
        timeout = _optional_float(context.parameters.get("timeout"), 10.0)
        outcome = self._fetch_attempt(url, timeout)
        if not outcome.evidence.has_signal and _param_bool(context, "fallback", True):
            fallback_scheme = "http" if _scheme(context) == "https" else "https"
            fallback = self._fetch_attempt(_build_url(context.target, fallback_scheme), timeout)
            if fallback.evidence.has_signal:
                outcome = fallback

        asset, asset_type = self._asset(context)
        observations = self._detector.detect(
            outcome.evidence,
            asset=asset,
            asset_type=asset_type,
            tool_id="signature",
            source="signature",
            target_id=self._target_id(context),
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
        )
        collector.set_exit_code(0)
        if outcome.error:
            collector.attach_stderr(outcome.error)
        collector.set_json(self._payload(observations))

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[TechnologyObservation]:
        """Unused for the in-process adapter; returns no observations."""
        return []

    def _fetch_attempt(self, url: str, timeout: float) -> _FetchOutcome:
        if self._cache is not None:
            cached = self._cache.get(_FETCH_CACHE_PREFIX + url)
            if isinstance(cached, HttpEvidence):
                return _FetchOutcome(evidence=cached)
        try:
            evidence = self._fetch(url, timeout)
        except Exception as exc:  # noqa: BLE001 - fetch failures become empty evidence
            return _FetchOutcome(
                evidence=HttpEvidence(url=url),
                error=f"fetch failed: {exc}",
            )
        if self._cache is not None:
            self._cache.set(
                _FETCH_CACHE_PREFIX + url,
                evidence,
                ttl_seconds=self._cache_ttl_s,
            )
        return _FetchOutcome(evidence=evidence)


def _build_url(target: str, scheme: str) -> str:
    """Build a fetchable URL from a typed target and scheme."""
    candidate = target.strip()
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return candidate
    return f"{scheme}://{candidate}"


def _scheme(context: ExecutionContext) -> str:
    value = context.parameters.get("scheme")
    if isinstance(value, str) and value.lower() in ("http", "https"):
        return value.lower()
    return "https"


def _param_bool(context: ExecutionContext, name: str, default: bool) -> bool:
    value = context.parameters.get(name, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes")


def _optional_float(value: object, default: float) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return default
