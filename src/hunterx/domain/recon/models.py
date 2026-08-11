# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reconnaissance domain models.

Pure data contracts for the reconnaissance capability: the canonical discovery
record every recon tool adapter produces, the target descriptor, the execution
mode, and the batch that carries correlated records back to the application
layer. No I/O and no execution here — adapters and services read and write
these structures.

Discovery records are deliberately tool-agnostic. Each :class:`DiscoveryRecord`
is a single observation of one asset kind (domain, subdomain, IP address, CIDR,
ASN, DNS record, certificate, WHOIS data, organisation, cloud provider or
exposed asset) with the tool that observed it, the upstream source, a
confidence score and an evidence ``details`` payload.

The TIDB ``network`` entities (:mod:`hunterx.domain.entities.tidb.network`)
are the persistence projection of these records; this module is the runtime
surface the capability pipeline is built on.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class DiscoveryKind(StrEnum):
    """Canonical kinds of asset a reconnaissance run can discover.

    Values map onto the TIDB network entity set where a table exists; the
    remaining kinds (organisation, cloud provider, exposed asset) are carried
    in the batch for reporting and knowledge use.
    """

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip-address"
    CIDR = "cidr"
    ASN = "asn"
    DNS_RECORD = "dns-record"
    CERTIFICATE = "certificate"
    WHOIS = "whois"
    ORGANIZATION = "organization"
    CLOUD_PROVIDER = "cloud-provider"
    EXPOSED_ASSET = "exposed-asset"


class ReconMode(StrEnum):
    """Execution posture of a reconnaissance run.

    ``PASSIVE`` uses purely passive sources (no direct interaction with the
    target infrastructure). ``ACTIVE`` resolves and queries the target. The
    ``HYBRID`` mode combines both, matching a mission's posture.
    """

    PASSIVE = "passive"
    ACTIVE = "active"
    HYBRID = "hybrid"


@dataclass(frozen=True, slots=True)
class ReconTarget:
    """A single reconnaissance target.

    Attributes:
        value: canonical target identifier (a domain, hostname or URL).
        target_type: canonical target kind (``domain``, ``host``, ``url``).
        target_id: owning target record id when the target is persisted.

    """

    value: str
    target_type: str = "domain"
    target_id: str = ""


@dataclass(frozen=True, slots=True)
class DiscoveryRecord:
    """A single asset observation produced by a recon tool adapter.

    Attributes:
        kind: the asset kind discovered.
        name: canonical identity of the asset (FQDN, IP, CIDR, ASN number,
            organisation name, URL...). Lowercased and trimmed.
        tool_id: the tool that produced the observation.
        source: upstream source of the observation (``crt.sh``, ``google``,
            ``passive``...) when known, otherwise empty.
        confidence: detection confidence in ``[0, 1]``.
        target_id: owning target record id when in-scope.
        details: evidence payload (addresses, record type, SANs, ...).
        observed_at: UTC ISO-8601 observation timestamp.
        record_id: stable identifier for this observation.

    """

    kind: DiscoveryKind
    name: str
    tool_id: str
    source: str = ""
    confidence: float = 1.0
    target_id: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=utcnow_iso)
    record_id: str = field(default_factory=generate_id, kw_only=True)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("discovery record name must not be empty")
        object.__setattr__(self, "name", self.name.strip().lower())

    def key(self) -> str:
        """Return the canonical deduplication key for this record.

        The key identifies the same logical asset regardless of which tool or
        source observed it, so correlators can merge corroborating records.
        """
        if self.kind is DiscoveryKind.ASN:
            number = str(self.details.get("number") or _asn_number(self.name))
            return f"asn:{number}"
        if self.kind is DiscoveryKind.DNS_RECORD:
            record_type = str(self.details.get("record_type") or "").upper()
            value = str(self.details.get("value") or "")
            return f"dns:{self.name}|{record_type}|{value}"
        if self.kind is DiscoveryKind.CERTIFICATE:
            fingerprint = str(self.details.get("sha256") or self.name.removeprefix("sha256:"))
            return f"cert:{fingerprint}"
        return f"{self.kind.value}:{self.name}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dictionary for pipeline serialization."""
        return {
            "record_id": self.record_id,
            "kind": self.kind.value,
            "name": self.name,
            "tool_id": self.tool_id,
            "source": self.source,
            "confidence": self.confidence,
            "target_id": self.target_id,
            "details": dict(self.details),
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> DiscoveryRecord:
        """Rebuild a record from a :meth:`to_dict` payload."""
        return cls(
            kind=DiscoveryKind(str(payload["kind"])),
            name=str(payload["name"]),
            tool_id=str(payload.get("tool_id") or ""),
            source=str(payload.get("source") or ""),
            confidence=float(payload.get("confidence") or 1.0),
            target_id=payload.get("target_id"),
            details=dict(payload.get("details") or {}),
            observed_at=str(payload.get("observed_at") or utcnow_iso()),
            record_id=str(payload.get("record_id") or generate_id()),
        )


@dataclass(frozen=True, slots=True)
class ReconExecutionSummary:
    """Outcome of running one recon tool through the execution engine.

    Attributes:
        tool_id: the tool executed.
        status: terminal execution status value (``completed``, ``failed``...).
        records: number of discovery records produced.
        duration_ms: execution duration in milliseconds.
        error: error message when the execution failed.

    """

    tool_id: str
    status: str
    records: int = 0
    duration_ms: int = 0
    error: str = ""


@dataclass(slots=True)
class ReconBatch:
    """The result of one reconnaissance run.

    Aggregates the correlated discovery records, per-tool execution summaries
    and the run's identity (mission, correlation id, target, mode).

    Attributes:
        mission_id: owning mission id (empty for ad-hoc runs).
        correlation_id: correlation id shared by every execution in the run.
        target: the target that was enumerated.
        mode: the execution posture used.
        records: correlated discovery records.
        executions: per-tool execution summaries.
        created_at: UTC ISO-8601 run timestamp.
        batch_id: stable identifier for this run.

    """

    mission_id: str
    correlation_id: str
    target: ReconTarget
    mode: ReconMode = ReconMode.HYBRID
    records: list[DiscoveryRecord] = field(default_factory=list)
    executions: list[ReconExecutionSummary] = field(default_factory=list)
    created_at: str = field(default_factory=utcnow_iso)
    batch_id: str = field(default_factory=generate_id, kw_only=True)

    def add_record(self, record: DiscoveryRecord) -> None:
        """Append a discovery record to the batch."""
        self.records.append(record)

    def add_records(self, records: list[DiscoveryRecord]) -> None:
        """Append several discovery records to the batch."""
        self.records.extend(records)

    def add_execution(self, summary: ReconExecutionSummary) -> None:
        """Append an execution summary to the batch."""
        self.executions.append(summary)

    def by_kind(self, kind: DiscoveryKind) -> list[DiscoveryRecord]:
        """Return the records of a single :class:`DiscoveryKind`."""
        return [record for record in self.records if record.kind is kind]

    def count(self) -> int:
        """Return the number of discovery records in the batch."""
        return len(self.records)

    def distinct(self) -> int:
        """Return the number of unique assets (by canonical key)."""
        return len({record.key() for record in self.records})


def _asn_number(name: str) -> int:
    """Extract a bare ASN number from names like ``AS13335`` or ``13335``."""
    candidate = name.removeprefix("AS").removeprefix("as")
    try:
        return int(candidate)
    except ValueError:
        return 0


def infer_ip_version(address: str) -> int:
    """Return the IP version of ``address`` (4 or 6)."""
    try:
        return ipaddress.ip_address(address).version
    except ValueError:
        return 4


def records_from_payload(payload: Mapping[str, Any] | None) -> list[DiscoveryRecord]:
    """Extract discovery records from a pipeline JSON payload.

    Adapters serialise their discoveries under the ``discoveries`` key of the
    JSON payload they attach to the :class:`~hunterx.domain.execution.ExecutionOutput`.
    This helper rebuilds the typed records so downstream services never touch
    raw dictionaries.
    """
    if not payload:
        return []
    discoveries = payload.get("discoveries")
    if not isinstance(discoveries, list):
        return []
    return [
        DiscoveryRecord.from_dict(entry)
        for entry in discoveries
        if isinstance(entry, dict)
    ]
