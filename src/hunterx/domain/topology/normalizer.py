# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology entity normalizer.

Collapses equivalent spellings of entity names into a single canonical form so
correlation never treats ``WWW.Example.COM.`` and ``www.example.com`` as
different assets. Deterministic and stateless.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.topology.enums import EntityKind
from hunterx.domain.topology.keys import (
    is_cidr,
    is_ip,
    normalize_cert_fingerprint,
    normalize_cidr,
    normalize_hostname,
    normalize_ip,
)


class TopologyNormalizer:
    """Normalize entity names to their canonical representation."""

    def normalize(self, kind: EntityKind | str, name: str) -> str:
        """Return the canonical form of ``name`` for the given entity kind."""
        kind = EntityKind(kind if isinstance(kind, str) else kind.value)
        return self._normalize(kind, name)

    def normalize_entity(self, kind: EntityKind | str, name: str, *, entity_id: str | None = None) -> Any:
        """Return a canonical :class:`TopologyEntity` for ``kind``/``name``."""
        from hunterx.domain.topology.models import TopologyEntity

        kind_enum = EntityKind(kind if isinstance(kind, str) else kind.value)
        canonical = self.normalize(kind_enum, name)
        return TopologyEntity(kind=kind_enum, name=canonical, entity_id=entity_id)

    def _normalize(self, kind: EntityKind, name: str) -> str:
        value = (name or "").strip()
        if kind in (EntityKind.HOSTNAME, EntityKind.DOMAIN, EntityKind.SUBDOMAIN, EntityKind.NAMESERVER, EntityKind.MX):
            return normalize_hostname(value)
        if kind == EntityKind.IP:
            if is_ip(value):
                return normalize_ip(value)
            return value
        if kind == EntityKind.CIDR:
            if is_cidr(value):
                return normalize_cidr(value)
            return value
        if kind == EntityKind.CERTIFICATE:
            return normalize_cert_fingerprint(value)
        return value
