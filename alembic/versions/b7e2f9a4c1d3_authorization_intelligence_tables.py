"""authorization intelligence tables

Revision ID: b7e2f9a4c1d3
Revises: 4a9c1d5f3e82
Create Date: 2026-08-09 16:00:00.000000

Extends the TIDB schema with the Wave 10 authorization & access-control
intelligence canonical inventory: subjects, roles, groups, permissions,
scopes, claims, policies, resources, actions, resource-identifier metadata,
ownership relationships, tenant boundaries, administrative surfaces,
function/object/field-level access-control indicators, frontend/backend
authorization logic, API authorization correlation, GraphQL/WebSocket/service
authorization, decision indicators, mass-assignment fields, generic
observations, evidence and historical-change records plus the run
observability record.

Security boundary: every table stores metadata and masked indicators only —
never raw passwords, token values, authorization-header values, JWT claims or
PII.

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b7e2f9a4c1d3'
down_revision: str | Sequence[str] | None = '4a9c1d5f3e82'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _envelope() -> list[sa.Column]:
    """Return the shared TIDB system-of-record columns."""
    return [
        sa.Column('id', sa.String(length=26), nullable=False),
        sa.Column('created_at', sa.String(length=32), nullable=False),
        sa.Column('updated_at', sa.String(length=32), nullable=True),
        sa.Column('first_seen', sa.String(length=32), nullable=True),
        sa.Column('last_seen', sa.String(length=32), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('revision', sa.Integer(), nullable=False),
        sa.Column('schema_version', sa.Integer(), nullable=False),
        sa.Column('deleted_at', sa.String(length=32), nullable=True),
        sa.Column('meta', sa.JSON(), nullable=False),
    ]


def _provenance() -> list[sa.Column]:
    """Return the shared provenance columns for authorization records."""
    return [
        sa.Column('source', sa.String(length=32), nullable=False, server_default='authorization'),
        sa.Column('tool_id', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('target_key', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('correlation_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
    ]


def upgrade() -> None:
    """Upgrade schema."""
    # -- authorization runs ---------------------------------------------------
    op.create_table('tidb_authorization_runs',
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('target_key', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('target_id', sa.String(length=26), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='running'),
        sa.Column('mode', sa.String(length=16), nullable=False, server_default='hybrid'),
        sa.Column('subjects', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('roles', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('permissions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('resources', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('actions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('admin_surfaces', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('function_level', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('object_level', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('field_level', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('changes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('conflicts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('started_at', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.Column('correlation_id', sa.String(length=26), nullable=False, server_default=''),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_runs_mission_id'), 'tidb_authorization_runs', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_runs_target_key'), 'tidb_authorization_runs', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_runs_correlation_id'), 'tidb_authorization_runs', ['correlation_id'], unique=False)

    # -- authorization subjects ----------------------------------------------
    op.create_table('tidb_authorization_subjects',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('subject_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('context', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_subjects_origin'), 'tidb_authorization_subjects', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_subjects_name'), 'tidb_authorization_subjects', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_subjects_subject_kind'), 'tidb_authorization_subjects', ['subject_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_subjects_target_key'), 'tidb_authorization_subjects', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_subjects_correlation_id'), 'tidb_authorization_subjects', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_subjects_mission_id'), 'tidb_authorization_subjects', ['mission_id'], unique=False)

    # -- authorization roles -------------------------------------------------
    op.create_table('tidb_authorization_roles',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('context', sa.Text(), nullable=False, server_default=''),
        sa.Column('default', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('custom', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_roles_origin'), 'tidb_authorization_roles', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_roles_name'), 'tidb_authorization_roles', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_roles_target_key'), 'tidb_authorization_roles', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_roles_correlation_id'), 'tidb_authorization_roles', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_roles_mission_id'), 'tidb_authorization_roles', ['mission_id'], unique=False)

    # -- authorization groups ------------------------------------------------
    op.create_table('tidb_authorization_groups',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('context', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_groups_origin'), 'tidb_authorization_groups', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_groups_name'), 'tidb_authorization_groups', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_groups_target_key'), 'tidb_authorization_groups', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_groups_correlation_id'), 'tidb_authorization_groups', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_groups_mission_id'), 'tidb_authorization_groups', ['mission_id'], unique=False)

    # -- authorization permissions -------------------------------------------
    op.create_table('tidb_authorization_permissions',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('action', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_permissions_origin'), 'tidb_authorization_permissions', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_permissions_name'), 'tidb_authorization_permissions', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_permissions_target_key'), 'tidb_authorization_permissions', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_permissions_correlation_id'), 'tidb_authorization_permissions', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_permissions_mission_id'), 'tidb_authorization_permissions', ['mission_id'], unique=False)

    # -- authorization scopes ------------------------------------------------
    op.create_table('tidb_authorization_scopes',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_scopes_origin'), 'tidb_authorization_scopes', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_scopes_name'), 'tidb_authorization_scopes', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_scopes_target_key'), 'tidb_authorization_scopes', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_scopes_correlation_id'), 'tidb_authorization_scopes', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_scopes_mission_id'), 'tidb_authorization_scopes', ['mission_id'], unique=False)

    # -- authorization claims ------------------------------------------------
    op.create_table('tidb_authorization_claims',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('value', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_claims_origin'), 'tidb_authorization_claims', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_claims_name'), 'tidb_authorization_claims', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_claims_target_key'), 'tidb_authorization_claims', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_claims_correlation_id'), 'tidb_authorization_claims', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_claims_mission_id'), 'tidb_authorization_claims', ['mission_id'], unique=False)

    # -- authorization policies ----------------------------------------------
    op.create_table('tidb_authorization_policies',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('model_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('mechanism', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_policies_origin'), 'tidb_authorization_policies', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_policies_model_kind'), 'tidb_authorization_policies', ['model_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_policies_target_key'), 'tidb_authorization_policies', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_policies_correlation_id'), 'tidb_authorization_policies', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_policies_mission_id'), 'tidb_authorization_policies', ['mission_id'], unique=False)

    # -- authorization resources ---------------------------------------------
    op.create_table('tidb_authorization_resources',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('resource_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('identifier', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('parent', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_resources_origin'), 'tidb_authorization_resources', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_resources_name'), 'tidb_authorization_resources', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_resources_resource_kind'), 'tidb_authorization_resources', ['resource_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_resources_target_key'), 'tidb_authorization_resources', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_resources_correlation_id'), 'tidb_authorization_resources', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_resources_mission_id'), 'tidb_authorization_resources', ['mission_id'], unique=False)

    # -- authorization actions -----------------------------------------------
    op.create_table('tidb_authorization_actions',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('original', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_actions_origin'), 'tidb_authorization_actions', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_actions_name'), 'tidb_authorization_actions', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_actions_target_key'), 'tidb_authorization_actions', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_actions_correlation_id'), 'tidb_authorization_actions', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_actions_mission_id'), 'tidb_authorization_actions', ['mission_id'], unique=False)

    # -- authorization identifiers -------------------------------------------
    op.create_table('tidb_authorization_identifiers',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('identifier', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('identifier_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('location', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_identifiers_origin'), 'tidb_authorization_identifiers', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_identifiers_identifier_kind'), 'tidb_authorization_identifiers', ['identifier_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_identifiers_target_key'), 'tidb_authorization_identifiers', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_identifiers_correlation_id'), 'tidb_authorization_identifiers', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_identifiers_mission_id'), 'tidb_authorization_identifiers', ['mission_id'], unique=False)

    # -- authorization ownership ---------------------------------------------
    op.create_table('tidb_authorization_ownership',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('ownership_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_ownership_origin'), 'tidb_authorization_ownership', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_ownership_name'), 'tidb_authorization_ownership', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_ownership_ownership_kind'), 'tidb_authorization_ownership', ['ownership_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_ownership_target_key'), 'tidb_authorization_ownership', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_ownership_correlation_id'), 'tidb_authorization_ownership', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_ownership_mission_id'), 'tidb_authorization_ownership', ['mission_id'], unique=False)

    # -- authorization tenants -----------------------------------------------
    op.create_table('tidb_authorization_tenants',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('tenant_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('location', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_tenants_origin'), 'tidb_authorization_tenants', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_tenants_name'), 'tidb_authorization_tenants', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_tenants_tenant_kind'), 'tidb_authorization_tenants', ['tenant_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_tenants_target_key'), 'tidb_authorization_tenants', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_tenants_correlation_id'), 'tidb_authorization_tenants', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_tenants_mission_id'), 'tidb_authorization_tenants', ['mission_id'], unique=False)

    # -- authorization admin surfaces ----------------------------------------
    op.create_table('tidb_authorization_admin_surfaces',
        sa.Column('url', sa.Text(), nullable=False, server_default=''),
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('surface_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('method', sa.String(length=16), nullable=False, server_default='GET'),
        sa.Column('api_id', sa.String(length=26), nullable=True),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_url'), 'tidb_authorization_admin_surfaces', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_origin'), 'tidb_authorization_admin_surfaces', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_surface_kind'), 'tidb_authorization_admin_surfaces', ['surface_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_api_id'), 'tidb_authorization_admin_surfaces', ['api_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_target_key'), 'tidb_authorization_admin_surfaces', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_correlation_id'), 'tidb_authorization_admin_surfaces', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_admin_surfaces_mission_id'), 'tidb_authorization_admin_surfaces', ['mission_id'], unique=False)

    # -- authorization function level ----------------------------------------
    op.create_table('tidb_authorization_function_level',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('function', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('method', sa.String(length=16), nullable=False, server_default='GET'),
        sa.Column('required_role', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_function_level_origin'), 'tidb_authorization_function_level', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_function_level_function'), 'tidb_authorization_function_level', ['function'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_function_level_target_key'), 'tidb_authorization_function_level', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_function_level_correlation_id'), 'tidb_authorization_function_level', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_function_level_mission_id'), 'tidb_authorization_function_level', ['mission_id'], unique=False)

    # -- authorization object level ------------------------------------------
    op.create_table('tidb_authorization_object_level',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('identifier', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('action', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('method', sa.String(length=16), nullable=False, server_default='GET'),
        sa.Column('parent_resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_object_level_origin'), 'tidb_authorization_object_level', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_object_level_resource'), 'tidb_authorization_object_level', ['resource'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_object_level_target_key'), 'tidb_authorization_object_level', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_object_level_correlation_id'), 'tidb_authorization_object_level', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_object_level_mission_id'), 'tidb_authorization_object_level', ['mission_id'], unique=False)

    # -- authorization field level -------------------------------------------
    op.create_table('tidb_authorization_field_level',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('field', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_field_level_origin'), 'tidb_authorization_field_level', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_field_level_field'), 'tidb_authorization_field_level', ['field'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_field_level_target_key'), 'tidb_authorization_field_level', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_field_level_correlation_id'), 'tidb_authorization_field_level', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_field_level_mission_id'), 'tidb_authorization_field_level', ['mission_id'], unique=False)

    # -- authorization frontend ----------------------------------------------
    op.create_table('tidb_authorization_frontend',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('check_type', sa.String(length=64), nullable=False, server_default='unknown'),
        sa.Column('target', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('js_asset', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_frontend_origin'), 'tidb_authorization_frontend', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_frontend_check_type'), 'tidb_authorization_frontend', ['check_type'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_frontend_target_key'), 'tidb_authorization_frontend', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_frontend_correlation_id'), 'tidb_authorization_frontend', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_frontend_mission_id'), 'tidb_authorization_frontend', ['mission_id'], unique=False)

    # -- authorization backend -----------------------------------------------
    op.create_table('tidb_authorization_backend',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('mechanism', sa.String(length=64), nullable=False, server_default='unknown'),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('target', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_backend_origin'), 'tidb_authorization_backend', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_backend_mechanism'), 'tidb_authorization_backend', ['mechanism'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_backend_target_key'), 'tidb_authorization_backend', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_backend_correlation_id'), 'tidb_authorization_backend', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_backend_mission_id'), 'tidb_authorization_backend', ['mission_id'], unique=False)

    # -- authorization api correlations --------------------------------------
    op.create_table('tidb_authorization_api_correlations',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('method', sa.String(length=16), nullable=False, server_default='GET'),
        sa.Column('authentication', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('role', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('scope', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('permission', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('action', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('tenant', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('policy', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('documented', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_api_correlations_origin'), 'tidb_authorization_api_correlations', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_api_correlations_endpoint'), 'tidb_authorization_api_correlations', ['endpoint'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_api_correlations_target_key'), 'tidb_authorization_api_correlations', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_api_correlations_correlation_id'), 'tidb_authorization_api_correlations', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_api_correlations_mission_id'), 'tidb_authorization_api_correlations', ['mission_id'], unique=False)

    # -- authorization graphql -----------------------------------------------
    op.create_table('tidb_authorization_graphql',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('subject', sa.String(length=32), nullable=False, server_default='field'),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('directive', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_graphql_origin'), 'tidb_authorization_graphql', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_graphql_subject'), 'tidb_authorization_graphql', ['subject'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_graphql_target_key'), 'tidb_authorization_graphql', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_graphql_correlation_id'), 'tidb_authorization_graphql', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_graphql_mission_id'), 'tidb_authorization_graphql', ['mission_id'], unique=False)

    # -- authorization websockets --------------------------------------------
    op.create_table('tidb_authorization_websockets',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('channel', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('mechanism', sa.String(length=64), nullable=False, server_default='unknown'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_websockets_origin'), 'tidb_authorization_websockets', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_websockets_mechanism'), 'tidb_authorization_websockets', ['mechanism'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_websockets_target_key'), 'tidb_authorization_websockets', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_websockets_correlation_id'), 'tidb_authorization_websockets', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_websockets_mission_id'), 'tidb_authorization_websockets', ['mission_id'], unique=False)

    # -- authorization services ----------------------------------------------
    op.create_table('tidb_authorization_services',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('service_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('mechanism', sa.String(length=64), nullable=False, server_default='unknown'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_services_origin'), 'tidb_authorization_services', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_services_name'), 'tidb_authorization_services', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_services_service_kind'), 'tidb_authorization_services', ['service_kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_services_target_key'), 'tidb_authorization_services', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_services_correlation_id'), 'tidb_authorization_services', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_services_mission_id'), 'tidb_authorization_services', ['mission_id'], unique=False)

    # -- authorization decisions ---------------------------------------------
    op.create_table('tidb_authorization_decisions',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('decision', sa.String(length=16), nullable=False, server_default='unknown'),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('method', sa.String(length=16), nullable=False, server_default='GET'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_decisions_origin'), 'tidb_authorization_decisions', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_decisions_decision'), 'tidb_authorization_decisions', ['decision'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_decisions_target_key'), 'tidb_authorization_decisions', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_decisions_correlation_id'), 'tidb_authorization_decisions', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_decisions_mission_id'), 'tidb_authorization_decisions', ['mission_id'], unique=False)

    # -- authorization mass assignment ---------------------------------------
    op.create_table('tidb_authorization_mass_assignment',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('model', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('fields', sa.JSON(), nullable=False),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_mass_assignment_origin'), 'tidb_authorization_mass_assignment', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_mass_assignment_model'), 'tidb_authorization_mass_assignment', ['model'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_mass_assignment_target_key'), 'tidb_authorization_mass_assignment', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_mass_assignment_correlation_id'), 'tidb_authorization_mass_assignment', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_mass_assignment_mission_id'), 'tidb_authorization_mass_assignment', ['mission_id'], unique=False)

    # -- authorization access control ----------------------------------------
    op.create_table('tidb_authorization_access_control',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('subject', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('relationship_type', sa.String(length=32), nullable=False, server_default='role'),
        sa.Column('target', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('resource', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_access_control_origin'), 'tidb_authorization_access_control', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_access_control_subject'), 'tidb_authorization_access_control', ['subject'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_access_control_relationship_type'), 'tidb_authorization_access_control', ['relationship_type'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_access_control_target_key'), 'tidb_authorization_access_control', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_access_control_correlation_id'), 'tidb_authorization_access_control', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_access_control_mission_id'), 'tidb_authorization_access_control', ['mission_id'], unique=False)

    # -- authorization observations ------------------------------------------
    op.create_table('tidb_authorization_observations',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('value', sa.Text(), nullable=False, server_default=''),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_observations_origin'), 'tidb_authorization_observations', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_observations_kind'), 'tidb_authorization_observations', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_observations_name'), 'tidb_authorization_observations', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_observations_target_key'), 'tidb_authorization_observations', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_observations_correlation_id'), 'tidb_authorization_observations', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_observations_mission_id'), 'tidb_authorization_observations', ['mission_id'], unique=False)

    # -- authorization evidence ----------------------------------------------
    op.create_table('tidb_authorization_evidence',
        sa.Column('subject_type', sa.String(length=32), nullable=False, server_default='resource'),
        sa.Column('subject_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('evidence_type', sa.String(length=32), nullable=False, server_default='other'),
        sa.Column('value', sa.Text(), nullable=False, server_default=''),
        sa.Column('source', sa.String(length=255), nullable=False, server_default='authorization'),
        sa.Column('strength', sa.String(length=16), nullable=False, server_default='moderate'),
        sa.Column('tool_id', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''),
        sa.Column('correlation_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_evidence_subject_type'), 'tidb_authorization_evidence', ['subject_type'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_evidence_subject_id'), 'tidb_authorization_evidence', ['subject_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_evidence_correlation_id'), 'tidb_authorization_evidence', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_evidence_mission_id'), 'tidb_authorization_evidence', ['mission_id'], unique=False)

    # -- authorization changes -----------------------------------------------
    op.create_table('tidb_authorization_changes',
        sa.Column('subject_type', sa.String(length=32), nullable=False, server_default='resource'),
        sa.Column('subject', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('change_type', sa.String(length=16), nullable=False, server_default='changed'),
        sa.Column('previous', sa.Text(), nullable=False, server_default=''),
        sa.Column('current', sa.Text(), nullable=False, server_default=''),
        sa.Column('tool_id', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('correlation_id', sa.String(length=26), nullable=False, server_default=''),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_authorization_changes_subject'), 'tidb_authorization_changes', ['subject'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_changes_mission_id'), 'tidb_authorization_changes', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_authorization_changes_correlation_id'), 'tidb_authorization_changes', ['correlation_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_authorization_changes_correlation_id'), table_name='tidb_authorization_changes')
    op.drop_index(op.f('ix_tidb_authorization_changes_mission_id'), table_name='tidb_authorization_changes')
    op.drop_index(op.f('ix_tidb_authorization_changes_subject'), table_name='tidb_authorization_changes')
    op.drop_table('tidb_authorization_changes')

    op.drop_index(op.f('ix_tidb_authorization_evidence_mission_id'), table_name='tidb_authorization_evidence')
    op.drop_index(op.f('ix_tidb_authorization_evidence_correlation_id'), table_name='tidb_authorization_evidence')
    op.drop_index(op.f('ix_tidb_authorization_evidence_subject_id'), table_name='tidb_authorization_evidence')
    op.drop_index(op.f('ix_tidb_authorization_evidence_subject_type'), table_name='tidb_authorization_evidence')
    op.drop_table('tidb_authorization_evidence')

    op.drop_index(op.f('ix_tidb_authorization_observations_mission_id'), table_name='tidb_authorization_observations')
    op.drop_index(op.f('ix_tidb_authorization_observations_correlation_id'), table_name='tidb_authorization_observations')
    op.drop_index(op.f('ix_tidb_authorization_observations_target_key'), table_name='tidb_authorization_observations')
    op.drop_index(op.f('ix_tidb_authorization_observations_name'), table_name='tidb_authorization_observations')
    op.drop_index(op.f('ix_tidb_authorization_observations_kind'), table_name='tidb_authorization_observations')
    op.drop_index(op.f('ix_tidb_authorization_observations_origin'), table_name='tidb_authorization_observations')
    op.drop_table('tidb_authorization_observations')

    op.drop_index(op.f('ix_tidb_authorization_access_control_mission_id'), table_name='tidb_authorization_access_control')
    op.drop_index(op.f('ix_tidb_authorization_access_control_correlation_id'), table_name='tidb_authorization_access_control')
    op.drop_index(op.f('ix_tidb_authorization_access_control_target_key'), table_name='tidb_authorization_access_control')
    op.drop_index(op.f('ix_tidb_authorization_access_control_relationship_type'), table_name='tidb_authorization_access_control')
    op.drop_index(op.f('ix_tidb_authorization_access_control_subject'), table_name='tidb_authorization_access_control')
    op.drop_index(op.f('ix_tidb_authorization_access_control_origin'), table_name='tidb_authorization_access_control')
    op.drop_table('tidb_authorization_access_control')

    op.drop_index(op.f('ix_tidb_authorization_mass_assignment_mission_id'), table_name='tidb_authorization_mass_assignment')
    op.drop_index(op.f('ix_tidb_authorization_mass_assignment_correlation_id'), table_name='tidb_authorization_mass_assignment')
    op.drop_index(op.f('ix_tidb_authorization_mass_assignment_target_key'), table_name='tidb_authorization_mass_assignment')
    op.drop_index(op.f('ix_tidb_authorization_mass_assignment_model'), table_name='tidb_authorization_mass_assignment')
    op.drop_index(op.f('ix_tidb_authorization_mass_assignment_origin'), table_name='tidb_authorization_mass_assignment')
    op.drop_table('tidb_authorization_mass_assignment')

    op.drop_index(op.f('ix_tidb_authorization_decisions_mission_id'), table_name='tidb_authorization_decisions')
    op.drop_index(op.f('ix_tidb_authorization_decisions_correlation_id'), table_name='tidb_authorization_decisions')
    op.drop_index(op.f('ix_tidb_authorization_decisions_target_key'), table_name='tidb_authorization_decisions')
    op.drop_index(op.f('ix_tidb_authorization_decisions_decision'), table_name='tidb_authorization_decisions')
    op.drop_index(op.f('ix_tidb_authorization_decisions_origin'), table_name='tidb_authorization_decisions')
    op.drop_table('tidb_authorization_decisions')

    op.drop_index(op.f('ix_tidb_authorization_services_mission_id'), table_name='tidb_authorization_services')
    op.drop_index(op.f('ix_tidb_authorization_services_correlation_id'), table_name='tidb_authorization_services')
    op.drop_index(op.f('ix_tidb_authorization_services_target_key'), table_name='tidb_authorization_services')
    op.drop_index(op.f('ix_tidb_authorization_services_service_kind'), table_name='tidb_authorization_services')
    op.drop_index(op.f('ix_tidb_authorization_services_name'), table_name='tidb_authorization_services')
    op.drop_index(op.f('ix_tidb_authorization_services_origin'), table_name='tidb_authorization_services')
    op.drop_table('tidb_authorization_services')

    op.drop_index(op.f('ix_tidb_authorization_websockets_mission_id'), table_name='tidb_authorization_websockets')
    op.drop_index(op.f('ix_tidb_authorization_websockets_correlation_id'), table_name='tidb_authorization_websockets')
    op.drop_index(op.f('ix_tidb_authorization_websockets_target_key'), table_name='tidb_authorization_websockets')
    op.drop_index(op.f('ix_tidb_authorization_websockets_mechanism'), table_name='tidb_authorization_websockets')
    op.drop_index(op.f('ix_tidb_authorization_websockets_origin'), table_name='tidb_authorization_websockets')
    op.drop_table('tidb_authorization_websockets')

    op.drop_index(op.f('ix_tidb_authorization_graphql_mission_id'), table_name='tidb_authorization_graphql')
    op.drop_index(op.f('ix_tidb_authorization_graphql_correlation_id'), table_name='tidb_authorization_graphql')
    op.drop_index(op.f('ix_tidb_authorization_graphql_target_key'), table_name='tidb_authorization_graphql')
    op.drop_index(op.f('ix_tidb_authorization_graphql_subject'), table_name='tidb_authorization_graphql')
    op.drop_index(op.f('ix_tidb_authorization_graphql_origin'), table_name='tidb_authorization_graphql')
    op.drop_table('tidb_authorization_graphql')

    op.drop_index(op.f('ix_tidb_authorization_api_correlations_mission_id'), table_name='tidb_authorization_api_correlations')
    op.drop_index(op.f('ix_tidb_authorization_api_correlations_correlation_id'), table_name='tidb_authorization_api_correlations')
    op.drop_index(op.f('ix_tidb_authorization_api_correlations_target_key'), table_name='tidb_authorization_api_correlations')
    op.drop_index(op.f('ix_tidb_authorization_api_correlations_endpoint'), table_name='tidb_authorization_api_correlations')
    op.drop_index(op.f('ix_tidb_authorization_api_correlations_origin'), table_name='tidb_authorization_api_correlations')
    op.drop_table('tidb_authorization_api_correlations')

    op.drop_index(op.f('ix_tidb_authorization_backend_mission_id'), table_name='tidb_authorization_backend')
    op.drop_index(op.f('ix_tidb_authorization_backend_correlation_id'), table_name='tidb_authorization_backend')
    op.drop_index(op.f('ix_tidb_authorization_backend_target_key'), table_name='tidb_authorization_backend')
    op.drop_index(op.f('ix_tidb_authorization_backend_mechanism'), table_name='tidb_authorization_backend')
    op.drop_index(op.f('ix_tidb_authorization_backend_origin'), table_name='tidb_authorization_backend')
    op.drop_table('tidb_authorization_backend')

    op.drop_index(op.f('ix_tidb_authorization_frontend_mission_id'), table_name='tidb_authorization_frontend')
    op.drop_index(op.f('ix_tidb_authorization_frontend_correlation_id'), table_name='tidb_authorization_frontend')
    op.drop_index(op.f('ix_tidb_authorization_frontend_target_key'), table_name='tidb_authorization_frontend')
    op.drop_index(op.f('ix_tidb_authorization_frontend_check_type'), table_name='tidb_authorization_frontend')
    op.drop_index(op.f('ix_tidb_authorization_frontend_origin'), table_name='tidb_authorization_frontend')
    op.drop_table('tidb_authorization_frontend')

    op.drop_index(op.f('ix_tidb_authorization_field_level_mission_id'), table_name='tidb_authorization_field_level')
    op.drop_index(op.f('ix_tidb_authorization_field_level_correlation_id'), table_name='tidb_authorization_field_level')
    op.drop_index(op.f('ix_tidb_authorization_field_level_target_key'), table_name='tidb_authorization_field_level')
    op.drop_index(op.f('ix_tidb_authorization_field_level_field'), table_name='tidb_authorization_field_level')
    op.drop_index(op.f('ix_tidb_authorization_field_level_origin'), table_name='tidb_authorization_field_level')
    op.drop_table('tidb_authorization_field_level')

    op.drop_index(op.f('ix_tidb_authorization_object_level_mission_id'), table_name='tidb_authorization_object_level')
    op.drop_index(op.f('ix_tidb_authorization_object_level_correlation_id'), table_name='tidb_authorization_object_level')
    op.drop_index(op.f('ix_tidb_authorization_object_level_target_key'), table_name='tidb_authorization_object_level')
    op.drop_index(op.f('ix_tidb_authorization_object_level_resource'), table_name='tidb_authorization_object_level')
    op.drop_index(op.f('ix_tidb_authorization_object_level_origin'), table_name='tidb_authorization_object_level')
    op.drop_table('tidb_authorization_object_level')

    op.drop_index(op.f('ix_tidb_authorization_function_level_mission_id'), table_name='tidb_authorization_function_level')
    op.drop_index(op.f('ix_tidb_authorization_function_level_correlation_id'), table_name='tidb_authorization_function_level')
    op.drop_index(op.f('ix_tidb_authorization_function_level_target_key'), table_name='tidb_authorization_function_level')
    op.drop_index(op.f('ix_tidb_authorization_function_level_function'), table_name='tidb_authorization_function_level')
    op.drop_index(op.f('ix_tidb_authorization_function_level_origin'), table_name='tidb_authorization_function_level')
    op.drop_table('tidb_authorization_function_level')

    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_mission_id'), table_name='tidb_authorization_admin_surfaces')
    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_correlation_id'), table_name='tidb_authorization_admin_surfaces')
    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_target_key'), table_name='tidb_authorization_admin_surfaces')
    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_api_id'), table_name='tidb_authorization_admin_surfaces')
    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_surface_kind'), table_name='tidb_authorization_admin_surfaces')
    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_origin'), table_name='tidb_authorization_admin_surfaces')
    op.drop_index(op.f('ix_tidb_authorization_admin_surfaces_url'), table_name='tidb_authorization_admin_surfaces')
    op.drop_table('tidb_authorization_admin_surfaces')

    op.drop_index(op.f('ix_tidb_authorization_tenants_mission_id'), table_name='tidb_authorization_tenants')
    op.drop_index(op.f('ix_tidb_authorization_tenants_correlation_id'), table_name='tidb_authorization_tenants')
    op.drop_index(op.f('ix_tidb_authorization_tenants_target_key'), table_name='tidb_authorization_tenants')
    op.drop_index(op.f('ix_tidb_authorization_tenants_tenant_kind'), table_name='tidb_authorization_tenants')
    op.drop_index(op.f('ix_tidb_authorization_tenants_name'), table_name='tidb_authorization_tenants')
    op.drop_index(op.f('ix_tidb_authorization_tenants_origin'), table_name='tidb_authorization_tenants')
    op.drop_table('tidb_authorization_tenants')

    op.drop_index(op.f('ix_tidb_authorization_ownership_mission_id'), table_name='tidb_authorization_ownership')
    op.drop_index(op.f('ix_tidb_authorization_ownership_correlation_id'), table_name='tidb_authorization_ownership')
    op.drop_index(op.f('ix_tidb_authorization_ownership_target_key'), table_name='tidb_authorization_ownership')
    op.drop_index(op.f('ix_tidb_authorization_ownership_ownership_kind'), table_name='tidb_authorization_ownership')
    op.drop_index(op.f('ix_tidb_authorization_ownership_name'), table_name='tidb_authorization_ownership')
    op.drop_index(op.f('ix_tidb_authorization_ownership_origin'), table_name='tidb_authorization_ownership')
    op.drop_table('tidb_authorization_ownership')

    op.drop_index(op.f('ix_tidb_authorization_identifiers_mission_id'), table_name='tidb_authorization_identifiers')
    op.drop_index(op.f('ix_tidb_authorization_identifiers_correlation_id'), table_name='tidb_authorization_identifiers')
    op.drop_index(op.f('ix_tidb_authorization_identifiers_target_key'), table_name='tidb_authorization_identifiers')
    op.drop_index(op.f('ix_tidb_authorization_identifiers_identifier_kind'), table_name='tidb_authorization_identifiers')
    op.drop_index(op.f('ix_tidb_authorization_identifiers_origin'), table_name='tidb_authorization_identifiers')
    op.drop_table('tidb_authorization_identifiers')

    op.drop_index(op.f('ix_tidb_authorization_actions_mission_id'), table_name='tidb_authorization_actions')
    op.drop_index(op.f('ix_tidb_authorization_actions_correlation_id'), table_name='tidb_authorization_actions')
    op.drop_index(op.f('ix_tidb_authorization_actions_target_key'), table_name='tidb_authorization_actions')
    op.drop_index(op.f('ix_tidb_authorization_actions_name'), table_name='tidb_authorization_actions')
    op.drop_index(op.f('ix_tidb_authorization_actions_origin'), table_name='tidb_authorization_actions')
    op.drop_table('tidb_authorization_actions')

    op.drop_index(op.f('ix_tidb_authorization_resources_mission_id'), table_name='tidb_authorization_resources')
    op.drop_index(op.f('ix_tidb_authorization_resources_correlation_id'), table_name='tidb_authorization_resources')
    op.drop_index(op.f('ix_tidb_authorization_resources_target_key'), table_name='tidb_authorization_resources')
    op.drop_index(op.f('ix_tidb_authorization_resources_resource_kind'), table_name='tidb_authorization_resources')
    op.drop_index(op.f('ix_tidb_authorization_resources_name'), table_name='tidb_authorization_resources')
    op.drop_index(op.f('ix_tidb_authorization_resources_origin'), table_name='tidb_authorization_resources')
    op.drop_table('tidb_authorization_resources')

    op.drop_index(op.f('ix_tidb_authorization_policies_mission_id'), table_name='tidb_authorization_policies')
    op.drop_index(op.f('ix_tidb_authorization_policies_correlation_id'), table_name='tidb_authorization_policies')
    op.drop_index(op.f('ix_tidb_authorization_policies_target_key'), table_name='tidb_authorization_policies')
    op.drop_index(op.f('ix_tidb_authorization_policies_model_kind'), table_name='tidb_authorization_policies')
    op.drop_index(op.f('ix_tidb_authorization_policies_origin'), table_name='tidb_authorization_policies')
    op.drop_table('tidb_authorization_policies')

    op.drop_index(op.f('ix_tidb_authorization_claims_mission_id'), table_name='tidb_authorization_claims')
    op.drop_index(op.f('ix_tidb_authorization_claims_correlation_id'), table_name='tidb_authorization_claims')
    op.drop_index(op.f('ix_tidb_authorization_claims_target_key'), table_name='tidb_authorization_claims')
    op.drop_index(op.f('ix_tidb_authorization_claims_name'), table_name='tidb_authorization_claims')
    op.drop_index(op.f('ix_tidb_authorization_claims_origin'), table_name='tidb_authorization_claims')
    op.drop_table('tidb_authorization_claims')

    op.drop_index(op.f('ix_tidb_authorization_scopes_mission_id'), table_name='tidb_authorization_scopes')
    op.drop_index(op.f('ix_tidb_authorization_scopes_correlation_id'), table_name='tidb_authorization_scopes')
    op.drop_index(op.f('ix_tidb_authorization_scopes_target_key'), table_name='tidb_authorization_scopes')
    op.drop_index(op.f('ix_tidb_authorization_scopes_name'), table_name='tidb_authorization_scopes')
    op.drop_index(op.f('ix_tidb_authorization_scopes_origin'), table_name='tidb_authorization_scopes')
    op.drop_table('tidb_authorization_scopes')

    op.drop_index(op.f('ix_tidb_authorization_permissions_mission_id'), table_name='tidb_authorization_permissions')
    op.drop_index(op.f('ix_tidb_authorization_permissions_correlation_id'), table_name='tidb_authorization_permissions')
    op.drop_index(op.f('ix_tidb_authorization_permissions_target_key'), table_name='tidb_authorization_permissions')
    op.drop_index(op.f('ix_tidb_authorization_permissions_name'), table_name='tidb_authorization_permissions')
    op.drop_index(op.f('ix_tidb_authorization_permissions_origin'), table_name='tidb_authorization_permissions')
    op.drop_table('tidb_authorization_permissions')

    op.drop_index(op.f('ix_tidb_authorization_groups_mission_id'), table_name='tidb_authorization_groups')
    op.drop_index(op.f('ix_tidb_authorization_groups_correlation_id'), table_name='tidb_authorization_groups')
    op.drop_index(op.f('ix_tidb_authorization_groups_target_key'), table_name='tidb_authorization_groups')
    op.drop_index(op.f('ix_tidb_authorization_groups_name'), table_name='tidb_authorization_groups')
    op.drop_index(op.f('ix_tidb_authorization_groups_origin'), table_name='tidb_authorization_groups')
    op.drop_table('tidb_authorization_groups')

    op.drop_index(op.f('ix_tidb_authorization_roles_mission_id'), table_name='tidb_authorization_roles')
    op.drop_index(op.f('ix_tidb_authorization_roles_correlation_id'), table_name='tidb_authorization_roles')
    op.drop_index(op.f('ix_tidb_authorization_roles_target_key'), table_name='tidb_authorization_roles')
    op.drop_index(op.f('ix_tidb_authorization_roles_name'), table_name='tidb_authorization_roles')
    op.drop_index(op.f('ix_tidb_authorization_roles_origin'), table_name='tidb_authorization_roles')
    op.drop_table('tidb_authorization_roles')

    op.drop_index(op.f('ix_tidb_authorization_subjects_mission_id'), table_name='tidb_authorization_subjects')
    op.drop_index(op.f('ix_tidb_authorization_subjects_correlation_id'), table_name='tidb_authorization_subjects')
    op.drop_index(op.f('ix_tidb_authorization_subjects_target_key'), table_name='tidb_authorization_subjects')
    op.drop_index(op.f('ix_tidb_authorization_subjects_subject_kind'), table_name='tidb_authorization_subjects')
    op.drop_index(op.f('ix_tidb_authorization_subjects_name'), table_name='tidb_authorization_subjects')
    op.drop_index(op.f('ix_tidb_authorization_subjects_origin'), table_name='tidb_authorization_subjects')
    op.drop_table('tidb_authorization_subjects')

    op.drop_index(op.f('ix_tidb_authorization_runs_correlation_id'), table_name='tidb_authorization_runs')
    op.drop_index(op.f('ix_tidb_authorization_runs_target_key'), table_name='tidb_authorization_runs')
    op.drop_index(op.f('ix_tidb_authorization_runs_mission_id'), table_name='tidb_authorization_runs')
    op.drop_table('tidb_authorization_runs')
