# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Relationship deriver.

Deterministic rules that turn canonical TIDB entities into raw relationship
observations. Every edge records its provenance source and evidence so the
correlator can merge, explain and preserve contradictions. The deriver is pure:
it consumes plain entity lists (already scoped) and produces observations.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from hunterx.domain.topology.models import RelationshipObservation, TopologyEntity, TopologySourceData
from hunterx.domain.topology.normalizer import TopologyNormalizer


class RelationshipDeriver:
    """Derive relationship observations from TIDB entities."""

    def __init__(
        self,
        normalizer: TopologyNormalizer | None = None,
        confidence: TopologyConfidenceEngine | None = None,
    ) -> None:
        self._normalizer = normalizer or TopologyNormalizer()
        self._confidence = confidence or TopologyConfidenceEngine()

    # -- public API ---------------------------------------------------------

    def derive(self, data: TopologySourceData, *, mission_id: str = "", correlation_id: str = "") -> list[RelationshipObservation]:
        """Derive every observation expressible from ``data``.

        Returns a deterministic list; duplicate edges are merged downstream by
        the correlator.
        """
        observations: list[RelationshipObservation] = []
        context = dict(mission_id=mission_id, correlation_id=correlation_id)

        domain_by_id = {d.id: d for d in data.domains}
        host_by_id = {h.id: h for h in data.hostnames}
        ip_by_id = {a.id: a for a in data.ip_addresses}
        cidr_by_id = {c.id: c for c in data.cidrs}
        asn_by_id = {a.id: a for a in data.asns}
        port_by_id = {p.id: p for p in data.ports}

        for obs in self._subdomain_domain(data.subdomains, domain_by_id, context):
            observations.append(obs)
        for obs in self._domain_parent(data.domains, context):
            observations.append(obs)
        for obs in self._hostname_domain(data.hostnames, domain_by_id, context):
            observations.append(obs)
        for obs in self._hostname_ip(data.ip_addresses, host_by_id, context):
            observations.append(obs)
        for obs in self._ip_cidr(data.ip_addresses, cidr_by_id, context):
            observations.append(obs)
        for obs in self._ip_asn(data.ip_addresses, asn_by_id, context):
            observations.append(obs)
        for obs in self._cidr_asn(data.cidrs, asn_by_id, context):
            observations.append(obs)
        for obs in self._ip_port(data.ports, ip_by_id, context):
            observations.append(obs)
        for obs in self._port_service(data.services, port_by_id, context):
            observations.append(obs)
        for obs in self._certificate_host(data.certificates, host_by_id, context):
            observations.append(obs)
        for obs in self._certificate_san(data.certificates, context):
            observations.append(obs)
        for obs in self._domain_nameservers(data.domains, data.nameservers, context):
            observations.append(obs)
        for obs in self._domain_mx(data.domains, data.mx_records, context):
            observations.append(obs)
        for obs in self._dns_records(data.dns_records, context):
            observations.append(obs)
        for obs in self._belongs_to(data.domains, data.hostnames, data.ip_addresses, data.targets, context):
            observations.append(obs)
        for obs in self._discovered_by(data.domains, data.hostnames, data.ip_addresses, context):
            observations.append(obs)
        for obs in self._observed_with(data.host_observations, data.service_observations, context):
            observations.append(obs)
        for obs in self._technology_uses(data.technology_observations, context):
            observations.append(obs)
        return observations

    # -- rules --------------------------------------------------------------

    def _subdomain_domain(self, subdomains, domain_by_id, context):
        for sub in subdomains:
            parent = domain_by_id.get(getattr(sub, "domain_id", None))
            if parent is None:
                continue
            yield self._obs(
                EntityKind.SUBDOMAIN, sub.name, EntityKind.DOMAIN, parent.name,
                RelationshipType.PART_OF, "tidb:subdomain", {"field": "domain_id", "entity_id": sub.id},
                **context,
            )

    def _domain_parent(self, domains, context):
        for dom in domains:
            parent_id = getattr(dom, "parent_domain_id", None)
            if not parent_id:
                continue
            parent = next((d for d in domains if d.id == parent_id), None)
            if parent is None:
                continue
            yield self._obs(
                EntityKind.DOMAIN, dom.name, EntityKind.DOMAIN, parent.name,
                RelationshipType.PART_OF, "tidb:domain", {"field": "parent_domain_id", "entity_id": dom.id},
                **context,
            )

    def _hostname_domain(self, hostnames, domain_by_id, context):
        for host in hostnames:
            name = (host.name or "").strip().lower()
            for dom in domain_by_id.values():
                if dom.name and name.endswith("." + dom.name):
                    yield self._obs(
                        EntityKind.HOSTNAME, host.name, EntityKind.DOMAIN, dom.name,
                        RelationshipType.PART_OF, "tidb:hostname", {"rule": "suffix", "entity_id": host.id},
                        **context,
                    )
                    break

    def _hostname_ip(self, ip_addresses, host_by_id, context):
        for addr in ip_addresses:
            host = host_by_id.get(getattr(addr, "hostname_id", None))
            if host is None:
                continue
            yield self._obs(
                EntityKind.HOSTNAME, host.name, EntityKind.IP, addr.address,
                RelationshipType.RESOLVES_TO, "tidb:ip", {"field": "hostname_id", "entity_id": addr.id},
                **context,
            )

    def _ip_cidr(self, ip_addresses, cidr_by_id, context):
        for addr in ip_addresses:
            cidr = cidr_by_id.get(getattr(addr, "cidr_id", None))
            if cidr is None:
                continue
            yield self._obs(
                EntityKind.IP, addr.address, EntityKind.CIDR, cidr.network,
                RelationshipType.PART_OF, "tidb:ip", {"field": "cidr_id", "entity_id": addr.id},
                **context,
            )

    def _ip_asn(self, ip_addresses, asn_by_id, context):
        for addr in ip_addresses:
            asn = asn_by_id.get(getattr(addr, "asn_id", None))
            if asn is None:
                continue
            yield self._obs(
                EntityKind.IP, addr.address, EntityKind.ASN, str(asn.number),
                RelationshipType.ANNOUNCED_BY, "tidb:ip", {"field": "asn_id", "entity_id": addr.id},
                **context,
            )

    def _cidr_asn(self, cidrs, asn_by_id, context):
        for cidr in cidrs:
            asn = asn_by_id.get(getattr(cidr, "asn_id", None))
            if asn is None:
                continue
            yield self._obs(
                EntityKind.CIDR, cidr.network, EntityKind.ASN, str(asn.number),
                RelationshipType.ANNOUNCED_BY, "tidb:cidr", {"field": "asn_id", "entity_id": cidr.id},
                **context,
            )

    def _ip_port(self, ports, ip_by_id, context):
        for port in ports:
            owner = ip_by_id.get(getattr(port, "ip_address_id", None))
            if owner is None:
                continue
            yield self._obs(
                EntityKind.IP, owner.address, EntityKind.PORT, f"{port.number}/{port.protocol}",
                RelationshipType.EXPOSES, "tidb:port", {"entity_id": port.id, "state": port.state.value if hasattr(port.state, "value") else port.state},
                **context,
            )

    def _port_service(self, services, port_by_id, context):
        for service in services:
            port = port_by_id.get(getattr(service, "port_id", None))
            if port is None:
                continue
            yield self._obs(
                EntityKind.PORT, f"{port.number}/{port.protocol}", EntityKind.SERVICE, service.name,
                RelationshipType.SERVES, "tidb:service", {"entity_id": service.id},
                **context,
            )

    def _certificate_host(self, certificates, host_by_id, context):
        for cert in certificates:
            host = host_by_id.get(getattr(cert, "hostname_id", None))
            if host is None:
                continue
            yield self._obs(
                EntityKind.HOSTNAME, host.name, EntityKind.CERTIFICATE, cert.sha256 or cert.serial or "",
                RelationshipType.USES, "tidb:certificate", {"entity_id": cert.id, "subject": cert.subject},
                **context,
            )

    def _certificate_san(self, certificates, context):
        for cert in certificates:
            fingerprint = cert.sha256 or cert.serial or ""
            if not fingerprint:
                continue
            for san in (cert.san or []):
                name = (san or "").strip()
                if not name:
                    continue
                yield self._obs(
                    EntityKind.CERTIFICATE, fingerprint, EntityKind.HOSTNAME, name,
                    RelationshipType.CERTIFICATE_FOR, "tidb:certificate", {"entity_id": cert.id, "san": True},
                    **context,
                )

    def _domain_nameservers(self, domains, nameservers, context):
        for dom in domains:
            for server in (dom.dns_servers or []):
                server = (server or "").strip().lower()
                if not server:
                    continue
                if nameservers:
                    owner = next((ns for ns in nameservers if (ns.owner_domain or "").strip().lower() == dom.name), None)
                    if owner is not None and (owner.name or "").strip().lower() != server:
                        continue
                yield self._obs(
                    EntityKind.DOMAIN, dom.name, EntityKind.NAMESERVER, server,
                    RelationshipType.DELEGATED_TO, "tidb:domain", {"field": "dns_servers", "entity_id": dom.id},
                    **context,
                )
            for ns in nameservers:
                if (ns.owner_domain or "").strip().lower() == dom.name:
                    yield self._obs(
                        EntityKind.DOMAIN, dom.name, EntityKind.NAMESERVER, ns.name,
                        RelationshipType.DELEGATED_TO, "tidb:nameserver", {"entity_id": ns.id},
                        **context,
                    )

    def _domain_mx(self, domains, mx_records, context):
        seen: set[tuple[str, str]] = set()
        for dom in domains:
            for exchange in (dom.mx or []):
                key = (dom.name, (exchange or "").strip().lower())
                if key in seen:
                    continue
                seen.add(key)
                if not exchange:
                    continue
                yield self._obs(
                    EntityKind.DOMAIN, dom.name, EntityKind.MX, exchange,
                    RelationshipType.MAILS_TO, "tidb:domain", {"field": "mx", "entity_id": dom.id},
                    **context,
                )
        for record in mx_records:
            if not record.exchange:
                continue
            owner = next((d for d in domains if d.id == getattr(record, "domain_id", None)), None)
            name = owner.name if owner is not None else record.name
            yield self._obs(
                EntityKind.DOMAIN, name, EntityKind.MX, record.exchange,
                RelationshipType.MAILS_TO, "tidb:mx_record", {"entity_id": record.id},
                **context,
            )

    def _dns_records(self, dns_records, context):
        for record in dns_records:
            value = record.record_type.value if hasattr(record.record_type, "value") else record.record_type
            rel = RelationshipType.RESOLVES_TO
            if str(value).upper() == "CNAME":
                rel = RelationshipType.POINTS_TO
            elif str(value).upper() == "MX":
                rel = RelationshipType.MAILS_TO
            yield self._obs(
                EntityKind.HOSTNAME, record.name, EntityKind.HOSTNAME, record.value,
                rel, "tidb:dns_record", {"entity_id": record.id, "record_type": str(value)},
                **context,
            )

    def _belongs_to(self, domains, hostnames, ip_addresses, targets, context):
        target_by_id = {}
        for t in targets:
            target_id = getattr(t, "id", None) or getattr(t, "target_id", None)
            if target_id:
                target_by_id[target_id] = t
        for dom in domains:
            target = target_by_id.get(getattr(dom, "target_id", None))
            if target is None:
                continue
            yield self._obs(
                EntityKind.DOMAIN, dom.name, EntityKind.TARGET, getattr(target, "value", "") or getattr(target, "name", ""),
                RelationshipType.BELONGS_TO, "tidb:domain", {"field": "target_id", "entity_id": dom.id},
                **context,
            )
        for host in hostnames:
            target = target_by_id.get(getattr(host, "target_id", None))
            if target is None:
                continue
            yield self._obs(
                EntityKind.HOSTNAME, host.name, EntityKind.TARGET, getattr(target, "value", "") or getattr(target, "name", ""),
                RelationshipType.BELONGS_TO, "tidb:hostname", {"field": "target_id", "entity_id": host.id},
                **context,
            )
        for addr in ip_addresses:
            target = target_by_id.get(getattr(addr, "target_id", None))
            if target is None:
                continue
            yield self._obs(
                EntityKind.IP, addr.address, EntityKind.TARGET, getattr(target, "value", "") or getattr(target, "name", ""),
                RelationshipType.BELONGS_TO, "tidb:ip", {"field": "target_id", "entity_id": addr.id},
                **context,
            )

    def _discovered_by(self, domains, hostnames, ip_addresses, context):
        for dom in domains:
            if getattr(dom, "source_tool", None):
                yield self._obs(
                    EntityKind.DOMAIN, dom.name, EntityKind.TOOL, dom.source_tool,
                    RelationshipType.DISCOVERED_BY, "tidb:domain", {"entity_id": dom.id},
                    **context,
                )
        for host in hostnames:
            if getattr(host, "source_tool", None):
                yield self._obs(
                    EntityKind.HOSTNAME, host.name, EntityKind.TOOL, host.source_tool,
                    RelationshipType.DISCOVERED_BY, "tidb:hostname", {"entity_id": host.id},
                    **context,
                )
        for addr in ip_addresses:
            if getattr(addr, "source_tool", None):
                yield self._obs(
                    EntityKind.IP, addr.address, EntityKind.TOOL, addr.source_tool,
                    RelationshipType.DISCOVERED_BY, "tidb:ip", {"entity_id": addr.id},
                    **context,
                )

    def _observed_with(self, host_observations, service_observations, context):
        seen: set[tuple[str, str]] = set()
        for host_obs in host_observations:
            hostname = getattr(host_obs, "hostname", "") or ""
            address = getattr(host_obs, "address", "") or ""
            if not hostname or not address:
                continue
            key = (hostname, address)
            if key in seen:
                continue
            seen.add(key)
            yield self._obs(
                EntityKind.HOSTNAME, hostname, EntityKind.IP, address,
                RelationshipType.OBSERVED_WITH, "tidb:host_observation", {"entity_id": host_obs.id},
                **context,
            )
        for svc_obs in service_observations:
            address = getattr(svc_obs, "address", "") or ""
            service = getattr(svc_obs, "service", "") or ""
            if not address or not service:
                continue
            key = (address, service)
            if key in seen:
                continue
            seen.add(key)
            yield self._obs(
                EntityKind.IP, address, EntityKind.SERVICE, service,
                RelationshipType.OBSERVED_WITH, "tidb:service_observation", {"entity_id": svc_obs.id},
                **context,
            )

    def _technology_uses(self, technology_observations, context):
        seen: set[tuple[str, str, str]] = set()
        for observation in technology_observations:
            asset = (getattr(observation, "asset", "") or "").strip().lower()
            name = (getattr(observation, "canonical_name", "") or getattr(observation, "raw_name", "") or "").strip()
            if not asset or not name:
                continue
            asset_type = (getattr(observation, "asset_type", "") or "").strip().lower()
            source_kind = {
                "hostname": EntityKind.HOSTNAME,
                "domain": EntityKind.DOMAIN,
                "ip": EntityKind.IP,
                "url": EntityKind.HOSTNAME,
                "service": EntityKind.SERVICE,
            }.get(asset_type, EntityKind.HOSTNAME)
            target_kind = _technology_kind((getattr(observation, "category", "") or "").strip().lower())
            key = (source_kind.value, asset, name)
            if key in seen:
                continue
            seen.add(key)
            yield self._obs(
                source_kind,
                asset,
                target_kind,
                name,
                RelationshipType.USES,
                "tidb:technology_observation",
                {
                    "entity_id": getattr(observation, "id", None),
                    "category": (getattr(observation, "category", "") or ""),
                    "version": (getattr(observation, "software_version", "") or ""),
                    "tool_id": (getattr(observation, "tool_id", "") or ""),
                },
                **context,
            )

    # -- helpers ------------------------------------------------------------

    def _obs(
        self,
        source_kind: EntityKind,
        source_name: str,
        target_kind: EntityKind,
        target_name: str,
        rel_type: RelationshipType,
        source_name_label: str,
        evidence: dict[str, Any],
        *,
        mission_id: str,
        correlation_id: str,
        confidence: float = 1.0,
    ) -> RelationshipObservation:
        return RelationshipObservation(
            rel_type=rel_type,
            source=self._node(source_kind, source_name),
            target=self._node(target_kind, target_name),
            source_name=source_name_label,
            evidence=evidence,
            confidence=self._confidence.combine([confidence], source_names=[source_name_label]),
            mission_id=mission_id,
            correlation_id=correlation_id,
        )

    def _node(self, kind: EntityKind, name: str) -> TopologyEntity:
        return self._normalizer.normalize_entity(kind, name)


def _technology_kind(category: str) -> EntityKind:
    """Map a technology category onto a canonical topology entity kind."""
    mapping = {
        "web-server": EntityKind.WEB_SERVER,
        "application-server": EntityKind.APPLICATION_SERVER,
        "cms": EntityKind.CMS,
        "framework": EntityKind.FRAMEWORK,
        "frontend": EntityKind.FRONTEND_FRAMEWORK,
        "backend": EntityKind.BACKEND_FRAMEWORK,
        "javascript": EntityKind.JAVASCRIPT,
        "programming-language": EntityKind.PROGRAMMING_LANGUAGE,
        "runtime": EntityKind.RUNTIME,
        "database": EntityKind.DATABASE,
        "operating-system": EntityKind.OPERATING_SYSTEM,
        "cdn": EntityKind.CDN,
        "waf": EntityKind.WAF,
        "proxy": EntityKind.REVERSE_PROXY,
        "load-balancer": EntityKind.LOAD_BALANCER,
        "cloud": EntityKind.CLOUD_PLATFORM,
        "hosting": EntityKind.HOSTING_PROVIDER,
    }
    return mapping.get(category, EntityKind.TECHNOLOGY)
