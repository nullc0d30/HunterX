# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Route observation models for topology tools.

Canonical hop-level observations produced by route-mapping tools (traceroute,
tracepath, mtr). A :class:`RouteRecord` describes one hop of a route; the
topology service translates consecutive hops into ``routes_to`` relationships
between IP nodes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class RouteRecord:
    """A single hop observed along a route to a target.

    Attributes:
        target: the route destination (IP or hostname).
        hop: hop number (1-based).
        address: hop IP address (``None`` for unreachable ``*`` hops).
        hostname: optional resolved hostname of the hop.
        rtt_ms: measured round-trip time in milliseconds (``None`` when lost).
        tool_id: tool that produced the observation.
        source: provenance label.

    """

    target: str
    hop: int
    address: str | None = None
    hostname: str | None = None
    rtt_ms: int | None = None
    tool_id: str = "traceroute"
    source: str = "traceroute"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the record to a JSON-safe mapping."""
        return {
            "target": self.target,
            "hop": self.hop,
            "address": self.address,
            "hostname": self.hostname,
            "rtt_ms": self.rtt_ms,
            "tool_id": self.tool_id,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RouteRecord:
        """Build a record from a payload mapping."""
        return cls(
            target=str(payload.get("target", "")),
            hop=int(payload.get("hop", 0)),
            address=payload.get("address"),
            hostname=payload.get("hostname"),
            rtt_ms=payload.get("rtt_ms"),
            tool_id=str(payload.get("tool_id", "traceroute")),
            source=str(payload.get("source", "traceroute")),
        )


def routes_from_payload(payload: dict[str, Any] | None) -> list[RouteRecord]:
    """Parse ``routes`` records from a tool payload."""
    if not payload or not isinstance(payload, dict):
        return []
    records: list[RouteRecord] = []
    for raw in payload.get("routes", []):
        if isinstance(raw, dict):
            records.append(RouteRecord.from_dict(raw))
    return records


def routes_to_payload(records: list[RouteRecord]) -> dict[str, Any]:
    """Serialize records into a tool payload."""
    return {
        "routes": [record.to_dict() for record in records],
        "count": len(records),
    }


def routes_to_observations(
    records: list[RouteRecord],
    *,
    mission_id: str = "",
    correlation_id: str = "",
    execution_id: str = "",
) -> list[Any]:
    """Convert consecutive route hops into ``routes_to`` observations.

    For a route ``[h1, h2, ..., hn, target]`` the emitted directed edges are
    ``h1 → h2 → ... → hn → target`` (unreachable asterisk hops are skipped).
    Returned observations are :class:`RelationshipObservation` instances ready
    for the topology correlator.
    """
    from hunterx.domain.topology.models import RelationshipObservation, TopologyEntity

    addresses: list[str] = []
    for record in records:
        if record.address:
            addresses.append(record.address)

    observations: list[Any] = []
    if not addresses:
        return observations

    from hunterx.domain.topology.keys import is_ip

    chain = list(addresses)
    final_target = records[-1].target if records else ""
    if final_target and is_ip(final_target):
        chain.append(final_target)
    chain = [hop for hop in chain if hop]
    for index in range(len(chain) - 1):
        source_ip = chain[index]
        target_ip = chain[index + 1]
        if source_ip == target_ip:
            continue
        observations.append(
            RelationshipObservation(
                rel_type="routes_to",
                source=TopologyEntity(kind="ip", name=source_ip),
                target=TopologyEntity(kind="ip", name=target_ip),
                source_name=records[0].source if records else "traceroute",
                evidence={
                    "tool_id": records[0].tool_id if records else "traceroute",
                    "target": records[-1].target if records else "",
                },
                confidence=0.8,
                mission_id=mission_id,
                execution_id=execution_id,
                correlation_id=correlation_id,
            )
        )
    return observations
