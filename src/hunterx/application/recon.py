# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reconnaissance use-case service.

The recon orchestrator — the bridge between a mission and the Tool Integration
SDK. Given a target and a posture, it selects the registered recon tools,
builds one :class:`ExecutionContext` per tool, runs each through the
:class:`ExecutionEngine` pipeline, collects the canonical discovery records,
correlates them across tools, persists them to the TIDB and publishes
``recon.*`` events.

The service depends on ports only: the execution engine (tools layer) and the
TIDB repository factory (domain port). Concrete SQL/in-memory stores are
injected by the platform assembler.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from hunterx.domain.entities.tidb.network import (
    ASN,
    CIDR,
    DNSRecord,
    DnsRecordType,
    Domain,
    Hostname,
    IPAddress,
    Subdomain,
    WHOISRecord,
)
from hunterx.domain.events.types import (
    ReconCompletedEvent,
    ReconCorrelatedEvent,
    ReconFailedEvent,
    ReconPersistedEvent,
    ReconStartedEvent,
    ReconToolCompletedEvent,
)
from hunterx.domain.execution import ExecutionContext
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.domain.recon.confidence import ConfidenceEngine, ConfidencePolicy
from hunterx.domain.recon.correlator import ReconCorrelator
from hunterx.domain.recon.models import (
    DiscoveryKind,
    DiscoveryRecord,
    ReconBatch,
    ReconExecutionSummary,
    ReconMode,
    ReconTarget,
    infer_ip_version,
    records_from_payload,
)
from hunterx.shared.ids import generate_id
from hunterx.tools.recon.registry import RECON_TOOL_IDS
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

#: Kinds persisted into the TIDB network entity set.
_PERSISTED_KINDS = frozenset(
    {
        DiscoveryKind.DOMAIN,
        DiscoveryKind.SUBDOMAIN,
        DiscoveryKind.HOSTNAME,
        DiscoveryKind.IP_ADDRESS,
        DiscoveryKind.CIDR,
        DiscoveryKind.ASN,
        DiscoveryKind.DNS_RECORD,
        DiscoveryKind.WHOIS,
        DiscoveryKind.CERTIFICATE,
    }
)


class ReconService:
    """Run reconnaissance missions through the Tool Integration SDK.

    Usage::

        service = ReconService(engine=engine, stores=stores, event_bus=bus)
        batch = service.run(mission_id="m1", target="example.com", mode="passive")
    """

    def __init__(
        self,
        *,
        engine: ExecutionEngine,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        correlator: ReconCorrelator | None = None,
        confidence: ConfidenceEngine | None = None,
        policy: ConfidencePolicy | None = None,
    ) -> None:
        self._engine = engine
        self._stores = stores
        self._event_bus = event_bus
        self._confidence = confidence or ConfidenceEngine(policy)
        self._correlator = correlator or ReconCorrelator(self._confidence)

    @property
    def engine(self) -> ExecutionEngine:
        """Return the execution engine used by this service."""
        return self._engine

    @property
    def correlator(self) -> ReconCorrelator:
        """Return the correlator used to merge discovery records."""
        return self._correlator

    def run(
        self,
        *,
        mission_id: str = "",
        target: ReconTarget | str,
        mode: ReconMode | str = ReconMode.HYBRID,
        tools: Sequence[str] | None = None,
        parameters: Mapping[str, Any] | None = None,
        scope: str = "",
    ) -> ReconBatch:
        """Execute a reconnaissance run and return the correlated batch.

        Args:
            mission_id: owning mission id (empty for ad-hoc runs).
            target: the target to enumerate (domain/hostname/URL).
            mode: the execution posture (passive, active or hybrid).
            tools: recon tool ids to run; defaults to every registered recon
                tool. Requesting an unregistered tool raises :class:`ValueError`.
            parameters: per-tool parameters merged into each execution context.
            scope: in-scope domain for correlation; defaults to the target.

        Returns:
            The :class:`ReconBatch` with correlated records and execution
            summaries.

        """
        recon_target = target if isinstance(target, ReconTarget) else _make_target(target)
        recon_mode = _make_mode(mode)
        selected = self._select_tools(tools)
        correlation_id = generate_id()
        parameters = dict(parameters or {})
        parameters["mode"] = recon_mode.value
        if recon_target.target_id:
            parameters["target_id"] = recon_target.target_id

        batch = ReconBatch(
            mission_id=mission_id,
            correlation_id=correlation_id,
            target=recon_target,
            mode=recon_mode,
        )
        self._publish(
            ReconStartedEvent(
                mission_id,
                correlation_id,
                recon_target.value,
                mode=recon_mode.value,
                tools=list(selected),
            )
        )

        raw_records: list[DiscoveryRecord] = []
        try:
            for tool_id in selected:
                context = self._build_context(
                    tool_id,
                    recon_target,
                    mission_id,
                    correlation_id,
                    parameters,
                )
                outcome = self._engine.execute(context)
                result = outcome.result
                tool_records = records_from_payload(result.output.json) if result.status.is_success else []
                raw_records.extend(tool_records)
                summary = ReconExecutionSummary(
                    tool_id=tool_id,
                    status=result.status.value,
                    records=len(tool_records),
                    duration_ms=result.duration_ms,
                    error=result.error,
                )
                batch.add_execution(summary)
                self._publish(
                    ReconToolCompletedEvent(
                        mission_id,
                        correlation_id,
                        tool_id,
                        summary.status,
                        records=summary.records,
                        duration_ms=summary.duration_ms,
                        error=summary.error,
                    )
                )

            correlated = self._correlator.correlate(raw_records, scope=scope or recon_target.value)
            batch.add_records(correlated)
            self._publish(
                ReconCorrelatedEvent(
                    mission_id,
                    correlation_id,
                    raw_records=len(raw_records),
                    correlated_records=len(correlated),
                    distinct_assets=batch.distinct(),
                )
            )

            persisted = 0
            if self._stores is not None:
                persisted = self._persist(batch, recon_target)
                self._publish(ReconPersistedEvent(mission_id, correlation_id, persisted=persisted))

            self._publish(
                ReconCompletedEvent(
                    mission_id,
                    correlation_id,
                    target=recon_target.value,
                    records=batch.count(),
                    distinct_assets=batch.distinct(),
                )
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a recon failure event
            self._publish(ReconFailedEvent(mission_id, correlation_id, str(exc)))
            raise
        return batch

    def _select_tools(self, tools: Sequence[str] | None) -> list[str]:
        """Return the registered recon tools to run for this mission."""
        registered = self._engine.adapter_for
        if tools is None:
            return [tool_id for tool_id in RECON_TOOL_IDS if registered(tool_id) is not None]
        requested = list(tools)
        missing = [tool_id for tool_id in requested if registered(tool_id) is None]
        if missing:
            raise ValueError(f"requested recon tools are not registered: {', '.join(missing)}")
        return requested

    def _build_context(
        self,
        tool_id: str,
        target: ReconTarget,
        mission_id: str,
        correlation_id: str,
        parameters: Mapping[str, Any],
    ) -> ExecutionContext:
        """Build an execution context for one recon tool."""
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=target.value)
            .with_mission(mission_id)
            .with_target_type(target.target_type)
            .with_profile("recon")
            .with_correlation_id(correlation_id)
            .with_permissions(("network",))
            .with_parameters(dict(parameters))
            .build()
        )

    def _persist(self, batch: ReconBatch, target: ReconTarget) -> int:
        """Persist correlated records into the TIDB; returns rows written."""
        stores = self._stores
        if stores is None:
            raise RuntimeError("cannot persist recon records without TIDB stores")
        persister = _ReconPersister(stores, target)
        count = 0
        for record in batch.records:
            if record.kind not in _PERSISTED_KINDS:
                continue
            count += persister.save(record)
        return count

    def _publish(self, event: Any) -> None:
        """Publish an event when an event bus is configured."""
        if self._event_bus is not None:
            self._event_bus.publish(event)


class _ReconPersister:
    """Maps discovery records onto TIDB network entities and saves them."""

    def __init__(self, stores: TidbRepositoryFactory, target: ReconTarget) -> None:
        self._stores = stores
        self._target = target
        self._domain_ids: dict[str, str] = {}

    def save(self, record: DiscoveryRecord) -> int:
        """Persist one record, returning the number of rows written."""
        method = {
            DiscoveryKind.DOMAIN: self._save_domain,
            DiscoveryKind.SUBDOMAIN: self._save_subdomain,
            DiscoveryKind.HOSTNAME: self._save_hostname,
            DiscoveryKind.IP_ADDRESS: self._save_ip,
            DiscoveryKind.CIDR: self._save_cidr,
            DiscoveryKind.ASN: self._save_asn,
            DiscoveryKind.DNS_RECORD: self._save_dns,
            DiscoveryKind.WHOIS: self._save_whois,
            DiscoveryKind.CERTIFICATE: self._save_certificate,
        }.get(record.kind)
        if method is None:
            return 0
        return method(record)

    # -- per-kind writers ---------------------------------------------------

    def _save_domain(self, record: DiscoveryRecord) -> int:
        domain = Domain(
            name=record.name,
            target_id=record.target_id or self._target.target_id or None,
            source_tool=record.tool_id,
            confidence=record.confidence,
        )
        self._stores.repository_for(Domain).save(domain)
        self._domain_ids[record.name] = domain.id
        return 1

    def _save_subdomain(self, record: DiscoveryRecord) -> int:
        parent_id = self._parent_domain_id(record.name)
        subdomain = Subdomain(domain_id=parent_id, name=record.name, resolution_confidence=record.confidence)
        self._stores.repository_for(Subdomain).save(subdomain)
        hostname = Hostname(name=record.name, target_id=record.target_id or self._target.target_id or None)
        self._stores.repository_for(Hostname).save(hostname)
        return 2

    def _save_hostname(self, record: DiscoveryRecord) -> int:
        hostname = Hostname(name=record.name, target_id=record.target_id or self._target.target_id or None)
        self._stores.repository_for(Hostname).save(hostname)
        return 1

    def _save_ip(self, record: DiscoveryRecord) -> int:
        ip = IPAddress(
            address=record.name,
            ip_version=infer_ip_version(record.name),
            target_id=record.target_id or self._target.target_id or None,
        )
        self._stores.repository_for(IPAddress).save(ip)
        return 1

    def _save_cidr(self, record: DiscoveryRecord) -> int:
        cidr = CIDR(network=record.name, target_id=record.target_id or self._target.target_id or None)
        self._stores.repository_for(CIDR).save(cidr)
        return 1

    def _save_asn(self, record: DiscoveryRecord) -> int:
        number = int(record.details.get("number") or 0)
        asn = ASN(
            number=number,
            name=_optional_str(record.details.get("name")) or "",
            org=_optional_str(record.details.get("org")),
            country=_optional_str(record.details.get("country")),
            registry=_optional_str(record.details.get("registry")),
        )
        self._stores.repository_for(ASN).save(asn)
        return 1

    def _save_dns(self, record: DiscoveryRecord) -> int:
        dns = DNSRecord(
            name=record.name,
            record_type=_dns_type(record.details.get("record_type")),
            value=_optional_str(record.details.get("value")) or "",
            ttl=_optional_int(record.details.get("ttl")),
            priority=_optional_int(record.details.get("priority")),
        )
        self._stores.repository_for(DNSRecord).save(dns)
        return 1

    def _save_whois(self, record: DiscoveryRecord) -> int:
        domain_id = self._domain_ids.get(record.name) or self._parent_domain_id(record.name)
        whois = WHOISRecord(
            domain_id=domain_id,
            raw=_optional_str(record.details.get("raw")) or "",
            registrar=_optional_str(record.details.get("registrar")),
            created_at_domain=_optional_str(record.details.get("created_at")),
            expires_at_domain=_optional_str(record.details.get("expires_at")),
            updated_at_domain=_optional_str(record.details.get("updated_at")),
            nameservers=_string_list(record.details.get("nameservers")),
        )
        self._stores.repository_for(WHOISRecord).save(whois)
        return 1

    def _save_certificate(self, record: DiscoveryRecord) -> int:
        from hunterx.domain.entities.tidb.network import Certificate

        certificate = Certificate(
            subject=_optional_str(record.details.get("subject")),
            issuer=_optional_str(record.details.get("issuer")),
            serial=_optional_str(record.details.get("serial")),
            sha256=_optional_str(record.details.get("sha256")) or record.name,
            not_before=_optional_str(record.details.get("not_before")),
            not_after=_optional_str(record.details.get("not_after")),
            san=_string_list(record.details.get("san")),
        )
        self._stores.repository_for(Certificate).save(certificate)
        return 1

    # -- helpers --------------------------------------------------------------

    def _parent_domain_id(self, name: str) -> str:
        """Resolve (or create) the parent domain id for ``name``.

        A parent domain only exists when ``name`` is a true subdomain (three or
        more labels, e.g. ``www.example.com`` → ``example.com``). Apex names
        (two labels) map back onto themselves so an apex observed as a
        subdomain never fabricates a spurious parent like ``com``.
        """
        if name.count(".") >= 2:
            parent = name.split(".", 1)[1]
            if parent not in self._domain_ids:
                self._ensure_domain(parent)
            return self._domain_ids[parent]
        return self._domain_ids.get(name) or self._ensure_domain(name)

    def _ensure_domain(self, name: str) -> str:
        """Create a parent domain record and cache its id."""
        domain = Domain(
            name=name,
            target_id=self._target.target_id or None,
            source_tool=None,
            confidence=0.5,
        )
        self._stores.repository_for(Domain).save(domain)
        self._domain_ids[name] = domain.id
        return domain.id


def _make_target(target: str) -> ReconTarget:
    """Build a :class:`ReconTarget` from a plain string."""
    stripped = target.strip()
    if stripped.startswith(("http://", "https://")):
        return ReconTarget(value=stripped, target_type="url")
    return ReconTarget(value=stripped, target_type="domain")


def _make_mode(mode: ReconMode | str) -> ReconMode:
    """Coerce a mode into a :class:`ReconMode`."""
    if isinstance(mode, ReconMode):
        return mode
    return ReconMode(str(mode).lower())


def _dns_type(value: object) -> DnsRecordType:
    """Coerce a record-type string into a :class:`DnsRecordType`."""
    name = str(value or "OTHER").upper()
    try:
        return DnsRecordType(name)
    except ValueError:
        return DnsRecordType.OTHER


def _optional_int(value: object) -> int | None:
    """Return an int value or ``None`` when not numeric."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _optional_str(value: object) -> str | None:
    """Return a string value or ``None``."""
    if value is None:
        return None
    return str(value)


def _string_list(value: object) -> list[str]:
    """Return a list of strings from a JSON-ish value."""
    if isinstance(value, list):
        return [str(item) for item in value]
    if value:
        return [str(value)]
    return []
