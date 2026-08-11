# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery domain package.

Pure, framework-free contracts and logic for the live host & service discovery
capability: host/port/service/TLS/HTTP observation models, normalization,
validation, confidence scoring, scope enforcement, correlation/conflict
handling, historical comparison and collection strategy.

The package depends only on the shared primitives and the recon domain for the
execution mode enum — no I/O, no tool calls and no persistence here.
"""

from hunterx.domain.livehost.confidence import LiveConfidenceEngine, LiveConfidencePolicy
from hunterx.domain.livehost.conflicts import LiveConflictResolver
from hunterx.domain.livehost.correlator import LiveCorrelationResult, LiveCorrelator, correlate_observations
from hunterx.domain.livehost.history import LiveHistory, LiveHistoryComparison
from hunterx.domain.livehost.models import (
    DEFAULT_TOP_PORTS,
    DiscoveryConflict,
    HostState,
    HttpFinding,
    LiveBatch,
    LiveChange,
    LiveExecutionSummary,
    LiveHost,
    LiveTarget,
    PortFinding,
    PortState,
    ReachabilityMethod,
    ReachabilityResult,
    ServiceFinding,
    TlsFinding,
    TransportProtocol,
    make_host,
    make_http,
    make_port,
    make_service,
    make_tls,
    observations_from_payload,
)
from hunterx.domain.livehost.normalizer import LiveNormalizer
from hunterx.domain.livehost.scope import LiveScopeEnforcer, LiveScopePolicy, ScopeDecision
from hunterx.domain.livehost.strategy import LiveStrategy, LiveStrategyBuilder
from hunterx.domain.livehost.validator import LiveValidationResult, LiveValidator

__all__ = [
    "DEFAULT_TOP_PORTS",
    "DiscoveryConflict",
    "HostState",
    "HttpFinding",
    "LiveBatch",
    "LiveChange",
    "LiveConfidenceEngine",
    "LiveConfidencePolicy",
    "LiveConflictResolver",
    "LiveCorrelationResult",
    "LiveCorrelator",
    "LiveExecutionSummary",
    "LiveHistory",
    "LiveHistoryComparison",
    "LiveHost",
    "LiveNormalizer",
    "LiveScopeEnforcer",
    "LiveScopePolicy",
    "LiveStrategy",
    "LiveStrategyBuilder",
    "LiveTarget",
    "LiveValidationResult",
    "LiveValidator",
    "PortFinding",
    "PortState",
    "ReachabilityMethod",
    "ReachabilityResult",
    "ScopeDecision",
    "ServiceFinding",
    "TlsFinding",
    "TransportProtocol",
    "correlate_observations",
    "make_host",
    "make_http",
    "make_port",
    "make_service",
    "make_tls",
    "observations_from_payload",
]
