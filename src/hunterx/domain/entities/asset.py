# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Asset entity.

An asset is a discovered resource within scope: a host, a service, a web
application, or a cloud resource. Assets form the graph nodes the knowledge
engine and correlation engine operate on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(slots=True)
class Asset(TidbEnvelopeMixin):
    """A discovered resource.

    Attributes:
        name: display name of the asset.
        asset_type: kind of asset (host, service, application, ...).
        mission_id: mission that discovered this asset.
        properties: JSON-serializable attribute map.
        updated_at / first_seen / last_seen / version / revision /
        schema_version / deleted_at: TIDB envelope.

    """

    name: str
    asset_type: str
    mission_id: str
    properties: dict[str, object] = field(default_factory=dict)
    asset_id: str = field(default_factory=generate_id)
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None
