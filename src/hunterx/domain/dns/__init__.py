# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS Intelligence domain package.

Pure, framework-free contracts and logic for the DNS intelligence capability:
record models, normalization, validation, confidence scoring, wildcard
detection, DNSSEC and mail analysis, correlation/conflict handling, historical
comparison, scope enforcement and collection strategy.

The package depends only on the shared primitives and the recon domain for the
execution mode enum — no I/O, no tool calls and no persistence here.
"""

from hunterx.domain.dns.confidence import DnsConfidenceEngine, DnsConfidencePolicy
from hunterx.domain.dns.conflicts import DnsConflict, DnsConflictResolver
from hunterx.domain.dns.correlator import DnsCorrelationResult, DnsCorrelator, correlate_records
from hunterx.domain.dns.dnssec import DnssecAnalyzer, DNSSECFinding
from hunterx.domain.dns.history import DnsChange, DnsHistory, HistoryComparison
from hunterx.domain.dns.mail import MailAnalyzer, MailInfrastructureFinding
from hunterx.domain.dns.models import (
    DnsBatch,
    DNSDelegation,
    DnsExecutionSummary,
    DNSObservation,
    DnsRecord,
    DnsRecordType,
    DNSResolution,
    DNSSECInfo,
    DnsTarget,
    DNSZone,
    MailInfrastructure,
    Nameserver,
    Resolver,
    WildcardFinding,
)
from hunterx.domain.dns.normalizer import DnsNormalizer
from hunterx.domain.dns.scope import ScopeDecision, ScopeEnforcer, ScopePolicy
from hunterx.domain.dns.strategy import DnsStrategy, DnsStrategyBuilder
from hunterx.domain.dns.validator import DnsValidationResult, DnsValidator
from hunterx.domain.dns.wildcard import WildcardDetector

__all__ = [
    "DNSDelegation",
    "DNSObservation",
    "DNSResolution",
    "DNSZone",
    "DNSSECFinding",
    "DNSSECInfo",
    "DnsBatch",
    "DnsChange",
    "DnsConflict",
    "DnsConflictResolver",
    "DnsConfidenceEngine",
    "DnsConfidencePolicy",
    "DnsCorrelator",
    "DnsCorrelationResult",
    "DnsExecutionSummary",
    "DnsHistory",
    "DnsNormalizer",
    "DnsRecord",
    "DnsRecordType",
    "DnsStrategy",
    "DnsStrategyBuilder",
    "DnsTarget",
    "DnsValidationResult",
    "DnsValidator",
    "DnssecAnalyzer",
    "HistoryComparison",
    "MailAnalyzer",
    "MailInfrastructure",
    "MailInfrastructureFinding",
    "Nameserver",
    "Resolver",
    "ScopeDecision",
    "ScopeEnforcer",
    "ScopePolicy",
    "WildcardDetector",
    "WildcardFinding",
    "correlate_records",
]
