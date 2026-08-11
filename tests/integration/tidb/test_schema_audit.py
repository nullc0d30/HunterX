# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Schema inventory & completeness audit (Sprint 034.3 §1, §2, §3, §11, §12).

Machine-checkable evidence that the critical TIDB tables, foreign keys,
indexes and uniqueness constraints exist after schema creation.
"""

from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")


CRITICAL_TABLES = [
    "tidb_intelligence_targets",
    "tidb_intelligence_assets",
    "tidb_intelligence_observations",
    "tidb_intelligence_evidence",
    "tidb_intelligence_hypotheses",
    "tidb_intelligence_history",
    "tidb_intelligence_changes",
    "tidb_intelligence_coverage",
    "tidb_domains",
    "tidb_subdomains",
    "tidb_hostnames",
    "tidb_ip_addresses",
    "tidb_cidrs",
    "tidb_asns",
    "tidb_dns_records",
    "tidb_ports",
    "tidb_services",
    "tidb_protocols",
    "tidb_technologies",
    "tidb_urls",
    "tidb_endpoints",
    "tidb_parameters",
    "tidb_apis",
    "tidb_rest_endpoints",
    "tidb_graphql_endpoints",
    "tidb_tool_executions",
    "tidb_executions",
    "tidb_execution_steps",
    "tidb_execution_events",
    "tidb_finding_records",
    "tidb_finding_pocs",
    "tidb_vulnerability_proofs",
    "tidb_proofs_of_concept",
    "tidb_proof_evidence",
    "tidb_proof_replays",
    "tidb_proof_impact_assessments",
    "tidb_adaptive_attack_paths",
    "tidb_attack_path_memories",
    "tidb_topology_relationships",
    "tidb_mission_orchestrations",
    "tidb_mission_runs",
    "tidb_mission_steps" if False else "tidb_mission_phases",
    "tidb_mission_hypotheses",
    "tidb_mission_observations",
    "tidb_mission_timelines",
    "tidb_mission_actions",
    "tidb_events" if False else "tidb_mission_impact",
    "tidb_audit_logs",
    "tidb_audit_events",
    "tidb_change_history",
    "tidb_version_history",
    "tidb_timeline_events",
    "tidb_users",
    "tidb_roles",
    "tidb_permissions",
    "tidb_secrets",
    "tidb_credentials",
    "tidb_api_keys",
    "tidb_tokens",
    "tidb_sessions",
    "tidb_jwts",
    "tidb_cves",
    "tidb_cwes",
    "tidb_capecs",
    "tidb_epss",
    "tidb_mitre_techniques",
    "tidb_cloud_resources",
    "tidb_cloud_saas_applications",
    "tidb_memory_observations",
    "tidb_campaigns",
]

# (table, column) → (referenced_table, referenced_column)
KEY_FOREIGN_KEYS = [
    ("tidb_subdomains", "domain_id", "tidb_domains", "id"),
    ("tidb_dns_records", "domain_id", "tidb_domains", "id"),
    ("tidb_ip_addresses", "hostname_id", "tidb_hostnames", "id"),
    ("tidb_ip_addresses", "cidr_id", "tidb_cidrs", "id"),
    ("tidb_cidrs", "asn_id", "tidb_asns", "id"),
    ("tidb_ports", "ip_address_id", "tidb_ip_addresses", "id"),
    ("tidb_services", "port_id", "tidb_ports", "id"),
    ("tidb_technologies", "service_id", "tidb_services", "id"),
    ("tidb_endpoints", "url_id", "tidb_urls", "id"),
    ("tidb_parameters", "endpoint_id", "tidb_endpoints", "id"),
    ("tidb_credentials", "secret_id", "tidb_secrets", "id"),
    ("tidb_api_keys", "secret_id", "tidb_secrets", "id"),
    ("tidb_tokens", "secret_id", "tidb_secrets", "id"),
    ("tidb_rest_endpoints", "api_id", "tidb_apis", "id"),
    ("tidb_authentication_schemes", "api_id", "tidb_apis", "id"),
]

# (table, index_name) — high-frequency query indexes
REQUIRED_INDEXES = [
    ("tidb_intelligence_targets", "ix_tidb_intelligence_targets_target_id"),
    ("tidb_intelligence_targets", "ix_tidb_intelligence_targets_mission_id"),
    ("tidb_intelligence_assets", "ix_tidb_intelligence_assets_target_id"),
    ("tidb_intelligence_observations", "ix_tidb_intelligence_observations_target_id"),
    ("tidb_intelligence_observations", "ix_tidb_intelligence_observations_mission_id"),
    ("tidb_intelligence_evidence", "ix_tidb_intelligence_evidence_target_id"),
    ("tidb_finding_records", "ix_tidb_finding_records_finding_id"),
    ("tidb_finding_records", "ix_tidb_finding_records_mission_id"),
    ("tidb_finding_records", "ix_tidb_finding_records_target_id"),
    ("tidb_finding_records", "ix_tidb_finding_records_severity"),
    ("tidb_finding_records", "ix_tidb_finding_records_status"),
    ("tidb_vulnerability_proofs", "ix_tidb_vulnerability_proofs_proof_id"),
    ("tidb_vulnerability_proofs", "ix_tidb_vulnerability_proofs_finding_id"),
    ("tidb_vulnerability_proofs", "ix_tidb_vulnerability_proofs_target_id"),
    ("tidb_tool_executions", "ix_tidb_tool_executions_execution_id"),
    ("tidb_mission_orchestrations", "ix_tidb_mission_orchestrations_mission_id"),
    ("tidb_mission_orchestrations", "ix_tidb_mission_orchestrations_tenant"),
]

# (table, column) — a uniqueness guarantee (unique constraint or unique index)
# must exist for the canonical key. Findings are additionally protected by the
# envelope primary key (the service sets ``id=finding_id``).
REQUIRED_UNIQUE = [
    ("tidb_domains", "name"),
    ("tidb_subdomains", "name"),
    ("tidb_ip_addresses", "address"),
    ("tidb_cidrs", "network"),
    ("tidb_urls", "url"),
    ("tidb_endpoints", "url_id"),
    ("tidb_parameters", "endpoint_id"),
]


def test_critical_tables_exist(session_factory) -> None:
    from sqlalchemy import inspect

    inspector = inspect(session_factory.engine)
    tables = set(inspector.get_table_names())
    missing = [t for t in CRITICAL_TABLES if t not in tables]
    assert not missing, f"missing tables: {missing}"


def test_key_foreign_keys_exist(session_factory) -> None:
    from sqlalchemy import inspect

    inspector = inspect(session_factory.engine)
    for table, column, ref_table, ref_column in KEY_FOREIGN_KEYS:
        fks = inspector.get_foreign_keys(table)
        match = any(
            fk.get("constrained_columns") == [column] and fk.get("referred_table") == ref_table
            for fk in fks
        )
        assert match, f"missing FK {table}.{column} -> {ref_table}.{ref_column}"


def test_required_indexes_exist(session_factory) -> None:
    from sqlalchemy import inspect

    inspector = inspect(session_factory.engine)
    for table, index_name in REQUIRED_INDEXES:
        indexes = {ix["name"] for ix in inspector.get_indexes(table)}
        assert index_name in indexes, f"missing index {table}.{index_name}"


def test_required_unique_constraints_exist(session_factory) -> None:
    from sqlalchemy import inspect

    inspector = inspect(session_factory.engine)
    for table, column in REQUIRED_UNIQUE:
        unique_constraints = {
            col
            for u in inspector.get_unique_constraints(table)
            for col in (u.get("column_names") or [])
        }
        unique_indexes = {
            col
            for ix in inspector.get_indexes(table)
            if ix.get("unique")
            for col in (ix.get("column_names") or [])
        }
        assert column in unique_constraints or column in unique_indexes, (
            f"missing uniqueness on {table}.{column}"
        )


def test_every_tidb_entity_has_an_orm_model(session_factory) -> None:
    """The generic registry must be able to resolve an ORM model for every TIDB
    entity exported by the domain package."""
    from hunterx.infrastructure.db.sql.registry import all_entities, model_class

    entities = {cls.__name__: cls for cls in all_entities()}
    for entity_cls in all_entities():
        # Every registered entity must have a corresponding ORM model.
        assert model_class(entity_cls) is not None
    assert len(entities) >= 100


def test_envelope_columns_present_on_every_table(session_factory) -> None:
    from sqlalchemy import inspect

    inspector = inspect(session_factory.engine)
    envelope = {"id", "created_at", "updated_at", "first_seen", "last_seen", "version", "revision", "schema_version", "deleted_at", "meta"}
    for table in inspector.get_table_names():
        if table.startswith("tidb_"):
            columns = {col["name"] for col in inspector.get_columns(table)}
            assert envelope.issubset(columns), f"table {table} missing envelope columns: {envelope - columns}"
