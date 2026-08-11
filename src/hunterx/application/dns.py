# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS intelligence use-case service.

The DNS orchestrator — the bridge between a mission and the DNS tooling. Given
a target and a posture, it builds a :class:`DnsStrategy`, selects the
registered DNS tools, runs each through the :class:`ExecutionEngine` pipeline,
collects the canonical records, validates, normalizes, correlates them across
tools, detects wildcards, analyzes DNSSEC and mail posture, compares against
historical state, persists everything to the TIDB and publishes ``dns.*``
events.

The service depends on ports only: the execution engine (tools layer), the
TIDB repository factory (domain port) and the cache port. Concrete
SQL/in-memory stores are injected by the platform assembler.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.dns.confidence import DnsConfidenceEngine
from hunterx.domain.dns.correlator import DnsCorrelator
from hunterx.domain.dns.dnssec import DnssecAnalyzer
from hunterx.domain.dns.history import DnsHistory
from hunterx.domain.dns.mail import MailAnalyzer
from hunterx.domain.dns.models import (
    DnsBatch,
    DnsExecutionSummary,
    DnsRecord,
    DnsRecordType,
    DNSResolution,
    DnsTarget,
    records_from_payload,
)
from hunterx.domain.dns.normalizer import DnsNormalizer
from hunterx.domain.dns.scope import ScopeEnforcer, ScopePolicy
from hunterx.domain.dns.strategy import DnsStrategy, DnsStrategyBuilder
from hunterx.domain.dns.validator import DnsValidator
from hunterx.domain.entities.tidb.network import DNSRecord as TidbDnsRecord
from hunterx.domain.events.types import (
    DnsChangeDetectedEvent,
    DnsConflictDetectedEvent,
    DnsCorrelationCompletedEvent,
    DnsIntelligenceCompletedEvent,
    DnsIntelligenceStartedEvent,
    DnsPhaseStartedEvent,
    DnsRecordDiscoveredEvent,
    DnsResolutionCompletedEvent,
    DnsResolutionFailedEvent,
    DnsResolutionStartedEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.models import ReconMode
from hunterx.shared.ids import generate_id
from hunterx.tools.dns.registry import DNS_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine


class DnsService:
    """Run DNS intelligence missions through the Tool Integration SDK.

    Usage::

        service = DnsService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="example.com", mode="active")
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        scope: ScopePolicy | None = None,
        cache: object | None = None,
        confidence: DnsConfidenceEngine | None = None,
        correlator: DnsCorrelator | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._scope = scope or ScopePolicy()
        self._cache = cache
        self._confidence = confidence or DnsConfidenceEngine()
        self._correlator = correlator or DnsCorrelator(scope=self._scope, confidence=self._confidence.policy)
        self._normalizer = DnsNormalizer()
        self._validator = DnsValidator()
        self._strategy_builder = DnsStrategyBuilder()
        self._scope_enforcer = ScopeEnforcer(self._scope)
        self._dnssec = DnssecAnalyzer()
        self._mail = MailAnalyzer()
        self._history = DnsHistory()

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> DnsCorrelator:
        """Return the correlator used to merge DNS records."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: DnsTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        with_dnssec: bool = False,
        with_mail: bool = False,
        with_wildcard: bool = False,
        with_history: bool = False,
        historical: Sequence[DnsRecord] | None = None,
    ) -> DnsBatch:
        """Execute a DNS intelligence run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to analyze (domain/hostname/IP).
            mode: the execution posture (passive, active or hybrid).
            tools: DNS tool ids to run; defaults to every registered DNS tool.
                Requesting an unregistered tool raises :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context.
            with_dnssec: analyze DNSSEC material.
            with_mail: analyze mail infrastructure (SPF/DMARC/DKIM).
            with_wildcard: probe for wildcard DNS.
            with_history: compare current records against ``historical``.
            historical: historical DNS records to diff against.

        Returns:
            The :class:`DnsBatch` with correlated records, observations,
            resolutions, findings and execution summaries.

        """
        dns_target = target if isinstance(target, DnsTarget) else _make_target(target)
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if dns_target.target_id:
            parameters["target_id"] = dns_target.target_id

        strategy = self._strategy_builder.build(
            dns_target.value,
            mode=recon_mode,
            target_kind=dns_target.target_type,
            with_dnssec=with_dnssec,
            with_mail=with_mail,
            with_wildcard=with_wildcard,
            with_history=with_history,
            active_resolvers=_resolver_list(parameters.get("resolvers")),
        )

        batch = DnsBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=dns_target,
            mode=recon_mode,
        )
        self._publish(
            DnsIntelligenceStartedEvent(
                mission_id,
                correlation_id,
                dns_target.value,
                mode=recon_mode.value,
                tools=list(selected),
            )
        )

        raw_records: list[DnsRecord] = []
        try:
            self._publish(DnsPhaseStartedEvent(correlation_id, "collection", mission_id=mission_id))
            for tool_id in selected:
                context = self._build_context(
                    tool_id,
                    dns_target,
                    mission_id,
                    correlation_id,
                    parameters,
                    strategy,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                tool_records = records_from_payload(result.output.json) if result.status.is_success else []
                raw_records.extend(tool_records)
                summary = DnsExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    records=len(tool_records),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)
                if not result.status.is_success:
                    self._publish(
                        DnsResolutionFailedEvent(
                            correlation_id,
                            dns_target.value,
                            result.error or result.status.value,
                            mission_id=mission_id,
                        )
                    )

            self._publish(DnsPhaseStartedEvent(correlation_id, "resolution", mission_id=mission_id))
            resolutions = self._resolve_targets(strategy, correlation_id, mission_id, dns_target.target_type)
            batch.resolutions.extend(resolutions)

            self._publish(DnsPhaseStartedEvent(correlation_id, "normalization", mission_id=mission_id))
            normalized = [self._normalizer.normalize(record) for record in raw_records]

            self._publish(DnsPhaseStartedEvent(correlation_id, "validation", mission_id=mission_id))
            validated: list[DnsRecord] = []
            for record in normalized:
                validation = self._validator.validate_record(record)
                validated.append(_set_validation(record, validation.status))
            normalized = validated

            self._publish(DnsPhaseStartedEvent(correlation_id, "correlation", mission_id=mission_id))
            correlated = self._correlator.correlate(normalized)
            in_scope = self._scope_enforcer.filter_records(correlated.records)
            batch.add_records(in_scope)
            for conflict in correlated.conflicts:
                batch.conflicts.append(
                    _to_batch_conflict(conflict, correlation_id)
                )
                self._publish(
                    DnsConflictDetectedEvent(
                        correlation_id,
                        conflict.name,
                        conflict.record_type.value,
                        list(conflict.values),
                        selected=conflict.selected,
                        mission_id=mission_id,
                    )
                )
            for record in in_scope:
                self._publish(
                    DnsRecordDiscoveredEvent(
                        correlation_id,
                        record.name,
                        record.record_type.value,
                        record.value,
                        tool_id=record.tool_id,
                        mission_id=mission_id,
                    )
                )
            self._publish(
                DnsCorrelationCompletedEvent(
                    mission_id,
                    correlation_id,
                    raw_records=len(raw_records),
                    correlated_records=len(in_scope),
                    conflicts=len(correlated.conflicts),
                )
            )

            self._publish(DnsPhaseStartedEvent(correlation_id, "analysis", mission_id=mission_id))
            if strategy.with_dnssec or with_dnssec:
                self._analyze_dnssec(batch, in_scope)
            if strategy.with_mail or with_mail:
                self._analyze_mail(batch, in_scope)
            if strategy.with_history and historical is not None:
                comparison = self._history.compare(historical, in_scope)
                for change in comparison.changes:
                    batch.changes.append(_to_batch_change(change, correlation_id))
                    self._publish(
                        DnsChangeDetectedEvent(
                            correlation_id,
                            change.name,
                            change.record_type.value,
                            change.change,
                            old_value=change.previous,
                            new_value=change.current,
                            mission_id=mission_id,
                        )
                    )

            if self._stores is not None:
                self._publish(DnsPhaseStartedEvent(correlation_id, "persistence", mission_id=mission_id))
                self._persist(batch, dns_target)

            self._publish(
                DnsIntelligenceCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=dns_target.value,
                    records=batch.count(),
                    distinct=batch.distinct(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a completion failure
            self._publish(
                DnsResolutionFailedEvent(correlation_id, dns_target.value, str(exc), mission_id=mission_id)
            )
            raise
        return batch

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered DNS tools to run for this mission."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in DNS_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested DNS tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: DnsTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
        strategy: DnsStrategy,
    ) -> ExecutionContext:
        """Build an execution context for one DNS tool."""
        merged = dict(parameters)
        merged.setdefault("record_types", [record_type.value for record_type in strategy.record_types])
        if strategy.active_resolvers:
            merged.setdefault("resolvers", list(strategy.active_resolvers))
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("dns")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(merged)
            .build()
        )

    def _resolve_targets(self, strategy: DnsStrategy, correlation_id: str, mission_id: str, target_type: str) -> list[DNSResolution]:
        """Resolve the target and record per-name outcomes."""
        resolutions: list[DNSResolution] = []
        names = [strategy.target]
        for name in names:
            self._publish(
                DnsResolutionStartedEvent(
                    correlation_id,
                    name,
                    record_types=[record_type.value for record_type in strategy.record_types],
                    mission_id=mission_id,
                )
            )
            try:
                resolution = _resolve_via_engine(self._engine, name, strategy, correlation_id)
            except Exception as exc:  # noqa: BLE001 - resolution failures are recorded, not fatal
                resolution = DNSResolution(name=name, status="error", error=str(exc))
                self._publish(
                    DnsResolutionFailedEvent(correlation_id, name, str(exc), mission_id=mission_id)
                )
            resolutions.append(resolution)
            self._publish(
                DnsResolutionCompletedEvent(
                    correlation_id,
                    name,
                    resolution.status,
                    records=len(resolution.record_types),
                    duration_ms=resolution.duration_ms,
                    mission_id=mission_id,
                )
            )
        return resolutions

    def _analyze_dnssec(self, batch: DnsBatch, records: Sequence[DnsRecord]) -> None:
        """Analyze DNSSEC posture for the zone and store the finding."""
        dnssec_records = [
            record
            for record in records
            if record.record_type
            in (DnsRecordType.DS, DnsRecordType.DNSKEY, DnsRecordType.RRSIG, DnsRecordType.NSEC, DnsRecordType.NSEC3)
        ]
        if not dnssec_records:
            return
        finding = self._dnssec.analyze(dnssec_records)
        from hunterx.domain.dns.models import DNSSECInfo

        batch.dnssec[finding.zone] = DNSSECInfo(
            domain=finding.zone,
            enabled=finding.status in ("secured",),
            has_ds=finding.has_ds,
            has_dnskey=finding.has_dnskey,
            has_rrsig=finding.signed,
            validation_state=finding.status,
            inconsistencies=tuple(detail for _passed, detail in finding.checks.values() if not _passed),
        )

    def _analyze_mail(self, batch: DnsBatch, records: Sequence[DnsRecord]) -> None:
        """Analyze mail posture for the domain and store the finding."""
        from hunterx.domain.dns.models import MailInfrastructure

        mail_records = [
            record
            for record in records
            if record.record_type in (DnsRecordType.TXT, DnsRecordType.MX)
        ]
        if not mail_records:
            return
        finding = self._mail.analyze(mail_records, domain=batch.target.value)
        mx_hosts = sorted(
            {
                record.value
                for record in mail_records
                if record.record_type is DnsRecordType.MX
            }
        )
        dmarc_records = [
            record.value
            for record in mail_records
            if record.record_type is DnsRecordType.TXT
            and record.value.strip().lower().startswith("v=dmarc1")
        ]
        batch.mail[finding.domain] = MailInfrastructure(
            domain=finding.domain,
            mx_hosts=tuple(mx_hosts),
            spf_record=finding.spf,
            spf_analysis={"valid": str(finding.spf_valid).lower(), "mechanisms": ",".join(finding.spf_mechanisms)},
            dmarc_record=dmarc_records[0] if dmarc_records else "",
            dmarc_analysis={"policy": finding.dmarc_policy, "rua": ",".join(finding.dmarc_rua)},
            dkim_selectors=finding.dkim_selectors,
            dkim_records={selector: "" for selector in finding.dkim_selectors},
            notes=(),
        )

    def _persist(self, batch: DnsBatch, target: DnsTarget) -> int:
        """Persist correlated records into the TIDB; returns rows written."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist DNS records without TIDB stores")
        persister = _DnsPersister(stores, target)
        count = 0
        for record in batch.records:
            count += persister.save(record)
        return count

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


class _DnsPersister:
    """Maps DNS records onto TIDB network entities and saves them."""

    def __init__(self, stores: TidbRepositoryFactory, target: DnsTarget) -> None:
        self._stores = stores
        self._target = target

    def save(self, record: DnsRecord) -> int:
        """Persist one record, returning the number of rows written."""
        tidb_record = TidbDnsRecord(
            name=record.name,
            record_type=_tidb_type(record.record_type),
            value=record.value,
            ttl=record.ttl,
            priority=record.priority,
        )
        self._stores.repository_for(TidbDnsRecord).save(tidb_record)
        return 1


def _make_target(target: str) -> DnsTarget:
    """Build a :class:`DnsTarget` from a plain string."""
    stripped = target.strip()
    if _is_ip(stripped):
        return DnsTarget(value=stripped, target_type="ip")
    if stripped.startswith(("http://", "https://")):
        return DnsTarget(value=stripped.split("//", 1)[1].split("/", 1)[0], target_type="domain")
    return DnsTarget(value=stripped, target_type="domain")


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _is_ip(value: str) -> bool:
    """Return whether ``value`` parses as an IP address."""
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _resolver_list(value: object) -> tuple[str, ...]:
    """Coerce a resolver parameter into a tuple of addresses."""
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    if isinstance(value, str) and value:
        return tuple(item.strip() for item in value.split(",") if item.strip())
    return ()


def _set_validation(record: DnsRecord, status: str) -> DnsRecord:
    """Return a record copy with the validation status applied."""
    return DnsRecord(
        name=record.name,
        record_type=record.record_type,
        value=record.value,
        raw_value=record.raw_value,
        ttl=record.ttl,
        priority=record.priority,
        source=record.source,
        tool_id=record.tool_id,
        resolver=record.resolver,
        observed_at=record.observed_at,
        execution_id=record.execution_id,
        correlation_id=record.correlation_id,
        target_id=record.target_id,
        validation_status=status,
        confidence=record.confidence,
        record_id=record.record_id,
    )


def _tidb_type(record_type: DnsRecordType) -> Any:
    """Map a DNS domain record type onto the TIDB enum."""
    from hunterx.domain.entities.tidb.network import DnsRecordType as TidbDnsRecordType

    try:
        return TidbDnsRecordType(record_type.value)
    except ValueError:
        return TidbDnsRecordType.OTHER


def _resolve_via_engine(engine: ExecutionEngine, name: str, strategy: DnsStrategy, correlation_id: str) -> DNSResolution:
    """Resolve a name through the engine's dnspython adapter when registered."""
    adapter = engine.adapter_for("dnspython")
    if adapter is None:
        return DNSResolution(name=name, status="skipped")
    context = (
        ExecutionContextBuilder(tool_id="dnspython", target=name)
        .with_target_type("domain")
        .with_profile("dns")
        .with_correlation_id(correlation_id)
        .with_permissions(("network",))
        .with_parameters(
            {
                "record_types": [record_type.value for record_type in strategy.record_types],
                "resolvers": list(strategy.active_resolvers),
            }
        )
        .build()
    )
    from hunterx.tools.sdk.output import OutputCollector

    collector = OutputCollector()
    from hunterx.tools.dns.base import DnsToolAdapter

    if not isinstance(adapter, DnsToolAdapter):
        return DNSResolution(name=name, status="skipped")
    adapter.run(context, collector)
    output = collector.build()
    records = records_from_payload(output.json)
    if not records:
        return DNSResolution(name=name, status="nxdomain")
    record_types = sorted({record.record_type.value for record in records})
    addresses = [record.value for record in records if record.record_type in (DnsRecordType.A, DnsRecordType.AAAA)]
    cnames = [record.value for record in records if record.record_type is DnsRecordType.CNAME]
    return DNSResolution(
        name=name,
        status="resolved",
        record_types=tuple(record_types),
        addresses=tuple(addresses),
        cnames=tuple(cnames),
    )


def _to_batch_conflict(conflict: Any, correlation_id: str) -> Any:
    """Map a correlator conflict onto the batch DNSConflict model."""
    from hunterx.domain.dns.models import DNSConflict

    return DNSConflict(
        name=conflict.name,
        record_type=conflict.record_type,
        observations=tuple(
            {"source": source, "value": conflict.selected} for source in conflict.sources
        ),
        conflict_type="value",
        selected_value=conflict.selected,
        selected_source=conflict.sources[0] if conflict.sources else "",
        reason=conflict.reason,
        confidence=conflict.confidence,
    )


def _to_batch_change(change: Any, correlation_id: str) -> Any:
    """Map a history change onto the batch DNSChange model."""
    from hunterx.domain.dns.models import DNSChange

    return DNSChange(
        name=change.name,
        record_type=change.record_type,
        change_type=change.change,
        old_value=change.previous,
        new_value=change.current,
        detected_at=change.observed_current or change.observed_previous,
        tool_id=change.source,
        confidence=0.9,
    )
