# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target entity.

A target is an authorized objective of a mission — a host, network range,
domain, or URL that the mission is allowed to interrogate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.domain.exceptions import InvalidTargetError
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class TargetKind(Enum):
    """Canonical target kinds."""

    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    HOST = "host"
    URL = "url"


@dataclass(slots=True)
class Target(TidbEnvelopeMixin):
    """An authorized mission objective.

    Attributes:
        kind: the kind of target.
        value: the target identifier (IP, CIDR, domain, hostname or URL).
        label: optional human-friendly name.
        metadata: free-form JSON-serializable attributes.
        program_id: owning scope program when in-scope.
        scope_status: TIDB scope status (authorized to interrogate).
        updated_at: last-write stamp (TIDB envelope).
        first_seen: first-observed stamp (TIDB envelope).
        last_seen: last-observed stamp (TIDB envelope).
        version: optimistic-lock version (TIDB envelope).
        revision: monotonic revision counter (TIDB envelope).
        schema_version: USS schema version (TIDB envelope).
        deleted_at: soft-delete stamp (TIDB envelope).

    """

    kind: TargetKind
    value: str
    label: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    target_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)
    program_id: str | None = None
    scope_status: str | None = None
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None

    def __post_init__(self) -> None:
        if not self.value:
            raise InvalidTargetError("target value must not be empty.")

    def identifier(self) -> str:
        """Return the canonical scope identifier for this target."""
        return f"{self.kind.value}:{self.value}"
