# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence entity.

Evidence is raw material backing up a finding: a command transcript, a packet
capture, a screenshot, a configuration file excerpt, or external data. It is
stored immutably in the object store and referenced by ID.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from hunterx.domain.entities._tidb_fields import TidbEnvelopeMixin
from hunterx.domain.exceptions import InvalidFindingError
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class EvidenceKind(Enum):
    """Canonical evidence kinds."""

    TRANSCRIPT = "transcript"
    SCREENSHOT = "screenshot"
    OUTPUT = "output"
    LOG = "log"
    FILE = "file"
    EXTERNAL = "external"


@dataclass(slots=True)
class Evidence(TidbEnvelopeMixin):
    """An immutable supporting artifact for a finding.

    Attributes:
        kind: kind of evidence.
        source: producing tool/component.
        content: textual content (or a content reference).
        mime_type: content MIME type.
        artifact_id: identity (auto-generated).
        object_key: key in the object store (populated when persisted).
        updated_at / first_seen / last_seen / version / revision /
        schema_version / deleted_at: TIDB envelope.

    """

    kind: EvidenceKind
    source: str
    content: str = ""
    mime_type: str = "text/plain"
    artifact_id: str = field(default_factory=generate_id)
    object_key: str | None = None
    created_at: str = field(default_factory=utcnow_iso)
    updated_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    version: int = 1
    revision: int = 1
    schema_version: int = 1
    deleted_at: str | None = None

    def __post_init__(self) -> None:
        if not self.source:
            raise InvalidFindingError("evidence source must not be empty.")
