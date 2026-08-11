# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the TIDB entity↔model registry and row mapper."""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    DNSRecord,
    DnsRecordType,
    Organization,
    Port,
    PortState,
    Program,
    ProgramStatus,
    Service,
    ServiceState,
)
from hunterx.infrastructure.db.sql.mapping import entity_to_mapping, to_entity, to_row
from hunterx.infrastructure.db.sql.registry import (
    ENTITY_TO_MODEL,
    MODEL_TO_ENTITY,
    all_entities,
    model_class,
)

sqlalchemy = pytest.importorskip("sqlalchemy")


def test_registry_covers_all_entities() -> None:
    entities = all_entities()
    assert len(entities) >= 85
    names = {cls.__name__ for cls in entities}
    for expected in ("Organization", "Program", "Domain", "URL", "CVE", "User", "APIClient"):
        assert expected in names


def test_registry_roundtrip_lookup() -> None:
    org_model = model_class(Organization)
    assert org_model.__name__ == "OrganizationModel"
    assert MODEL_TO_ENTITY[org_model] is Organization
    assert ENTITY_TO_MODEL[Organization] is org_model


def test_row_mapper_roundtrip_with_enums() -> None:
    program = Program(organization_id="org-1", name="scope-a", status=ProgramStatus.PAUSED)
    row = to_row(program)
    assert row.name == "scope-a"
    assert row.status == "paused"

    back = to_entity(Program, row)
    assert back == program
    assert back.status is ProgramStatus.PAUSED


def test_row_mapper_network_entities() -> None:
    dns = DNSRecord(name="api.example.com", record_type=DnsRecordType.TXT, value="v=spf1")
    port = Port(ip_address_id="ip-1", number=8443, state=PortState.FILTERED)
    service = Service(port_id="p-1", name="https", state=ServiceState.UP)

    assert to_entity(DNSRecord, to_row(dns)) == dns
    assert to_entity(Port, to_row(port)).state is PortState.FILTERED
    assert to_entity(Service, to_row(service)).state is ServiceState.UP


def test_row_mapper_json_columns() -> None:
    org = Organization(name="Acme", industry="security", meta={"env": "prod"})
    row = to_row(org)
    assert row.meta == {"env": "prod"}
    assert to_entity(Organization, row).meta == {"env": "prod"}


def test_entity_to_mapping_serializes_enums() -> None:
    mapping = entity_to_mapping(Program(organization_id="x", name="scope", status=ProgramStatus.ACTIVE))
    assert mapping["status"] == "active"
    assert mapping["organization_id"] == "x"


def test_unknown_entity_has_no_model() -> None:
    class NotAnEntity:  # noqa: D101
        pass

    with pytest.raises(LookupError):
        model_class(NotAnEntity)
