"""authentication intelligence tables

Revision ID: 4a9c1d5f3e82
Revises: 371b8ca7642d
Create Date: 2026-08-09 14:00:00.000000

Extends the TIDB schema with the Wave 9 authentication, session & identity
intelligence canonical inventory: authentication surfaces, endpoints, modeled
flows, identity providers, OAuth/OIDC/SAML configurations, authentication
schemes, cookie security metadata, token-storage indicators, CSRF mechanisms,
CORS policies, MFA/WebAuthn mechanisms, role/scope/permission/tenant indicators,
generic observations, evidence and historical-change records plus the run
observability record.

Security boundary: every table stores metadata and masked indicators only —
never raw passwords, token values, session-cookie values or OTP/recovery codes.

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '4a9c1d5f3e82'
down_revision: str | Sequence[str] | None = '371b8ca7642d'
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
    """Return the shared provenance columns for auth intelligence records."""
    return [
        sa.Column('source', sa.String(length=32), nullable=False, server_default='auth'),
        sa.Column('tool_id', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('target_key', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('correlation_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
    ]


def upgrade() -> None:
    """Upgrade schema."""
    # -- auth runs -----------------------------------------------------------
    op.create_table('tidb_auth_runs',
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('target_key', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('target_id', sa.String(length=26), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='running'),
        sa.Column('mode', sa.String(length=16), nullable=False, server_default='hybrid'),
        sa.Column('surfaces', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('endpoints', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('flows', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('identity_providers', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('oauth_configs', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('oidc_configs', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('saml_configs', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('schemes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('cookies', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('mfa', sa.Integer(), nullable=False, server_default='0'),
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
    op.create_index(op.f('ix_tidb_auth_runs_mission_id'), 'tidb_auth_runs', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_runs_target_key'), 'tidb_auth_runs', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_runs_correlation_id'), 'tidb_auth_runs', ['correlation_id'], unique=False)

    # -- auth surfaces -------------------------------------------------------
    op.create_table('tidb_auth_surfaces',
        sa.Column('url', sa.Text(), nullable=False, server_default=''),
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('surface_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('access_state', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_auth_surfaces_url'), 'tidb_auth_surfaces', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_auth_surfaces_origin'), 'tidb_auth_surfaces', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_auth_surfaces_surface_kind'), 'tidb_auth_surfaces', ['surface_kind'], unique=False)
    op.create_index(op.f('ix_tidb_auth_surfaces_access_state'), 'tidb_auth_surfaces', ['access_state'], unique=False)
    op.create_index(op.f('ix_tidb_auth_surfaces_target_key'), 'tidb_auth_surfaces', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_surfaces_correlation_id'), 'tidb_auth_surfaces', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_surfaces_mission_id'), 'tidb_auth_surfaces', ['mission_id'], unique=False)

    # -- auth endpoints ------------------------------------------------------
    op.create_table('tidb_auth_endpoints',
        sa.Column('url', sa.Text(), nullable=False, server_default=''),
        sa.Column('method', sa.String(length=16), nullable=False, server_default='GET'),
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('api_id', sa.String(length=26), nullable=True),
        sa.Column('documented', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_auth_endpoints_url'), 'tidb_auth_endpoints', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_auth_endpoints_origin'), 'tidb_auth_endpoints', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_auth_endpoints_kind'), 'tidb_auth_endpoints', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_auth_endpoints_api_id'), 'tidb_auth_endpoints', ['api_id'], unique=False)
    op.create_index('ix_tidb_auth_endpoints_url_kind', 'tidb_auth_endpoints', ['url', 'kind'], unique=False)
    op.create_index(op.f('ix_tidb_auth_endpoints_target_key'), 'tidb_auth_endpoints', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_endpoints_correlation_id'), 'tidb_auth_endpoints', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_endpoints_mission_id'), 'tidb_auth_endpoints', ['mission_id'], unique=False)

    # -- auth flows ----------------------------------------------------------
    op.create_table('tidb_auth_flows',
        sa.Column('name', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('flow_kind', sa.String(length=32), nullable=False, server_default='custom'),
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('start_state', sa.String(length=32), nullable=False, server_default='anonymous'),
        sa.Column('end_state', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('steps', sa.JSON(), nullable=False),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_auth_flows_name'), 'tidb_auth_flows', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_auth_flows_flow_kind'), 'tidb_auth_flows', ['flow_kind'], unique=False)
    op.create_index(op.f('ix_tidb_auth_flows_origin'), 'tidb_auth_flows', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_auth_flows_target_key'), 'tidb_auth_flows', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_flows_correlation_id'), 'tidb_auth_flows', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_flows_mission_id'), 'tidb_auth_flows', ['mission_id'], unique=False)

    # -- identity providers --------------------------------------------------
    op.create_table('tidb_identity_providers',
        sa.Column('name', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('provider_kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('issuer', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('discovery_url', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('endpoints', sa.JSON(), nullable=False),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_identity_providers_name'), 'tidb_identity_providers', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_identity_providers_provider_kind'), 'tidb_identity_providers', ['provider_kind'], unique=False)
    op.create_index(op.f('ix_tidb_identity_providers_origin'), 'tidb_identity_providers', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_identity_providers_target_key'), 'tidb_identity_providers', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_identity_providers_correlation_id'), 'tidb_identity_providers', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_identity_providers_mission_id'), 'tidb_identity_providers', ['mission_id'], unique=False)

    # -- oauth configs -------------------------------------------------------
    op.create_table('tidb_oauth_configs',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('authorization_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('token_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('revocation_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('introspection_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('userinfo_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('issuer', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('jwks_uri', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('client_ids', sa.JSON(), nullable=False),
        sa.Column('redirect_uris', sa.JSON(), nullable=False),
        sa.Column('scopes', sa.JSON(), nullable=False),
        sa.Column('response_types', sa.JSON(), nullable=False),
        sa.Column('grant_types', sa.JSON(), nullable=False),
        sa.Column('pkce', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('state_parameter', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_oauth_configs_origin'), 'tidb_oauth_configs', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_oauth_configs_target_key'), 'tidb_oauth_configs', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_oauth_configs_correlation_id'), 'tidb_oauth_configs', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_oauth_configs_mission_id'), 'tidb_oauth_configs', ['mission_id'], unique=False)

    # -- oidc configs --------------------------------------------------------
    op.create_table('tidb_oidc_configs',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('issuer', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('discovery_url', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('authorization_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('token_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('userinfo_endpoint', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('jwks_uri', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('scopes', sa.JSON(), nullable=False),
        sa.Column('claims', sa.JSON(), nullable=False),
        sa.Column('response_types', sa.JSON(), nullable=False),
        sa.Column('subject_types', sa.JSON(), nullable=False),
        sa.Column('id_token_signing_alg_values', sa.JSON(), nullable=False),
        sa.Column('code_challenge_methods_supported', sa.JSON(), nullable=False),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_oidc_configs_origin'), 'tidb_oidc_configs', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_oidc_configs_target_key'), 'tidb_oidc_configs', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_oidc_configs_correlation_id'), 'tidb_oidc_configs', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_oidc_configs_mission_id'), 'tidb_oidc_configs', ['mission_id'], unique=False)

    # -- saml configs --------------------------------------------------------
    op.create_table('tidb_saml_configs',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('entity_id', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('sso_url', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('acs_url', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('metadata_url', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('idp_name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('sp_name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('relay_state', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_saml_configs_origin'), 'tidb_saml_configs', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_saml_configs_target_key'), 'tidb_saml_configs', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_saml_configs_correlation_id'), 'tidb_saml_configs', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_saml_configs_mission_id'), 'tidb_saml_configs', ['mission_id'], unique=False)

    # -- auth schemes --------------------------------------------------------
    op.create_table('tidb_auth_schemes',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('api_id', sa.String(length=26), nullable=True),
        sa.Column('scheme_type', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('token_location', sa.String(length=32), nullable=False, server_default='header'),
        sa.Column('header_name', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('documented', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_auth_schemes_origin'), 'tidb_auth_schemes', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_auth_schemes_api_id'), 'tidb_auth_schemes', ['api_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_schemes_scheme_type'), 'tidb_auth_schemes', ['scheme_type'], unique=False)
    op.create_index('ix_tidb_auth_schemes_origin_type', 'tidb_auth_schemes', ['origin', 'scheme_type'], unique=False)
    op.create_index(op.f('ix_tidb_auth_schemes_target_key'), 'tidb_auth_schemes', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_schemes_correlation_id'), 'tidb_auth_schemes', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_schemes_mission_id'), 'tidb_auth_schemes', ['mission_id'], unique=False)

    # -- auth cookies --------------------------------------------------------
    op.create_table('tidb_auth_cookies',
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('domain', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('path', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('secure', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('httponly', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('partitioned', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('samesite', sa.String(length=16), nullable=False, server_default='unknown'),
        sa.Column('max_age', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('expires', sa.String(length=64), nullable=False, server_default=''),
        sa.Column('priority', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('prefix', sa.String(length=32), nullable=False, server_default=''),
        sa.Column('session', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('persistent', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_auth_cookies_name'), 'tidb_auth_cookies', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_auth_cookies_origin'), 'tidb_auth_cookies', ['origin'], unique=False)
    op.create_index('ix_tidb_auth_cookies_name_origin', 'tidb_auth_cookies', ['name', 'origin'], unique=False)
    op.create_index(op.f('ix_tidb_auth_cookies_target_key'), 'tidb_auth_cookies', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_cookies_correlation_id'), 'tidb_auth_cookies', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_cookies_mission_id'), 'tidb_auth_cookies', ['mission_id'], unique=False)

    # -- token storage indicators --------------------------------------------
    op.create_table('tidb_token_storage_indicators',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('storage_type', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('context', sa.Text(), nullable=False, server_default=''),
        sa.Column('token_category', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('js_asset', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_token_storage_indicators_origin'), 'tidb_token_storage_indicators', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_token_storage_indicators_storage_type'), 'tidb_token_storage_indicators', ['storage_type'], unique=False)
    op.create_index(op.f('ix_tidb_token_storage_indicators_token_category'), 'tidb_token_storage_indicators', ['token_category'], unique=False)
    op.create_index(op.f('ix_tidb_token_storage_indicators_target_key'), 'tidb_token_storage_indicators', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_token_storage_indicators_correlation_id'), 'tidb_token_storage_indicators', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_token_storage_indicators_mission_id'), 'tidb_token_storage_indicators', ['mission_id'], unique=False)

    # -- csrf mechanisms -----------------------------------------------------
    op.create_table('tidb_csrf_mechanisms',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('cookie_name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('header_name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('parameter_name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('samesite', sa.String(length=16), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_csrf_mechanisms_origin'), 'tidb_csrf_mechanisms', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_csrf_mechanisms_kind'), 'tidb_csrf_mechanisms', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_csrf_mechanisms_target_key'), 'tidb_csrf_mechanisms', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_csrf_mechanisms_correlation_id'), 'tidb_csrf_mechanisms', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_csrf_mechanisms_mission_id'), 'tidb_csrf_mechanisms', ['mission_id'], unique=False)

    # -- cors policies -------------------------------------------------------
    op.create_table('tidb_cors_policies',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('allow_origin', sa.Text(), nullable=False, server_default=''),
        sa.Column('allow_credentials', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('allow_methods', sa.JSON(), nullable=False),
        sa.Column('allow_headers', sa.JSON(), nullable=False),
        sa.Column('expose_headers', sa.JSON(), nullable=False),
        sa.Column('preflight', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.5'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_cors_policies_origin'), 'tidb_cors_policies', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_cors_policies_target_key'), 'tidb_cors_policies', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_cors_policies_correlation_id'), 'tidb_cors_policies', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_cors_policies_mission_id'), 'tidb_cors_policies', ['mission_id'], unique=False)

    # -- mfa mechanisms ------------------------------------------------------
    op.create_table('tidb_mfa_mechanisms',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
        sa.Column('ui', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mfa_mechanisms_origin'), 'tidb_mfa_mechanisms', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_mfa_mechanisms_kind'), 'tidb_mfa_mechanisms', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_mfa_mechanisms_target_key'), 'tidb_mfa_mechanisms', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_mfa_mechanisms_correlation_id'), 'tidb_mfa_mechanisms', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_mfa_mechanisms_mission_id'), 'tidb_mfa_mechanisms', ['mission_id'], unique=False)

    # -- webauthn indicators -------------------------------------------------
    op.create_table('tidb_webauthn_indicators',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('kind', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('api', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('js_asset', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('challenge_ref', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.4'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_webauthn_indicators_origin'), 'tidb_webauthn_indicators', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_webauthn_indicators_kind'), 'tidb_webauthn_indicators', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_webauthn_indicators_target_key'), 'tidb_webauthn_indicators', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_webauthn_indicators_correlation_id'), 'tidb_webauthn_indicators', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_webauthn_indicators_mission_id'), 'tidb_webauthn_indicators', ['mission_id'], unique=False)

    # -- role indicators -----------------------------------------------------
    op.create_table('tidb_role_indicators',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('context', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_role_indicators_origin'), 'tidb_role_indicators', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_role_indicators_name'), 'tidb_role_indicators', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_role_indicators_target_key'), 'tidb_role_indicators', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_role_indicators_correlation_id'), 'tidb_role_indicators', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_role_indicators_mission_id'), 'tidb_role_indicators', ['mission_id'], unique=False)

    # -- scope indicators ----------------------------------------------------
    op.create_table('tidb_scope_indicators',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_scope_indicators_origin'), 'tidb_scope_indicators', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_scope_indicators_name'), 'tidb_scope_indicators', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_scope_indicators_target_key'), 'tidb_scope_indicators', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_scope_indicators_correlation_id'), 'tidb_scope_indicators', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_scope_indicators_mission_id'), 'tidb_scope_indicators', ['mission_id'], unique=False)

    # -- permission indicators -----------------------------------------------
    op.create_table('tidb_permission_indicators',
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
    op.create_index(op.f('ix_tidb_permission_indicators_origin'), 'tidb_permission_indicators', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_permission_indicators_name'), 'tidb_permission_indicators', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_permission_indicators_target_key'), 'tidb_permission_indicators', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_permission_indicators_correlation_id'), 'tidb_permission_indicators', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_permission_indicators_mission_id'), 'tidb_permission_indicators', ['mission_id'], unique=False)

    # -- tenant indicators ---------------------------------------------------
    op.create_table('tidb_tenant_indicators',
        sa.Column('origin', sa.String(length=512), nullable=False, server_default=''),
        sa.Column('name', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('tenant_type', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('location', sa.String(length=255), nullable=False, server_default=''),
        sa.Column('api_id', sa.String(length=26), nullable=True),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='0.3'),
        *_provenance(),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_tenant_indicators_origin'), 'tidb_tenant_indicators', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_tenant_indicators_name'), 'tidb_tenant_indicators', ['name'], unique=False)
    op.create_index(op.f('ix_tidb_tenant_indicators_tenant_type'), 'tidb_tenant_indicators', ['tenant_type'], unique=False)
    op.create_index(op.f('ix_tidb_tenant_indicators_api_id'), 'tidb_tenant_indicators', ['api_id'], unique=False)
    op.create_index(op.f('ix_tidb_tenant_indicators_target_key'), 'tidb_tenant_indicators', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_tenant_indicators_correlation_id'), 'tidb_tenant_indicators', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_tenant_indicators_mission_id'), 'tidb_tenant_indicators', ['mission_id'], unique=False)

    # -- auth observations ---------------------------------------------------
    op.create_table('tidb_auth_observations',
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
    op.create_index(op.f('ix_tidb_auth_observations_origin'), 'tidb_auth_observations', ['origin'], unique=False)
    op.create_index(op.f('ix_tidb_auth_observations_kind'), 'tidb_auth_observations', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_auth_observations_name'), 'tidb_auth_observations', ['name'], unique=False)
    op.create_index('ix_tidb_auth_observations_origin_kind', 'tidb_auth_observations', ['origin', 'kind'], unique=False)
    op.create_index(op.f('ix_tidb_auth_observations_target_key'), 'tidb_auth_observations', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_auth_observations_correlation_id'), 'tidb_auth_observations', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_observations_mission_id'), 'tidb_auth_observations', ['mission_id'], unique=False)

    # -- auth evidence -------------------------------------------------------
    op.create_table('tidb_auth_evidence',
        sa.Column('subject_type', sa.String(length=32), nullable=False, server_default='observation'),
        sa.Column('subject_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('evidence_type', sa.String(length=32), nullable=False, server_default='other'),
        sa.Column('value', sa.Text(), nullable=False, server_default=''),
        sa.Column('source', sa.String(length=255), nullable=False, server_default='auth'),
        sa.Column('strength', sa.String(length=16), nullable=False, server_default='moderate'),
        sa.Column('tool_id', sa.String(length=128), nullable=False, server_default=''),
        sa.Column('detail', sa.Text(), nullable=False, server_default=''),
        sa.Column('correlation_id', sa.String(length=26), nullable=False, server_default=''),
        sa.Column('mission_id', sa.String(length=26), nullable=False, server_default=''),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_auth_evidence_subject_type'), 'tidb_auth_evidence', ['subject_type'], unique=False)
    op.create_index(op.f('ix_tidb_auth_evidence_subject_id'), 'tidb_auth_evidence', ['subject_id'], unique=False)
    op.create_index('ix_tidb_auth_evidence_subject', 'tidb_auth_evidence', ['subject_type', 'subject_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_evidence_correlation_id'), 'tidb_auth_evidence', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_evidence_mission_id'), 'tidb_auth_evidence', ['mission_id'], unique=False)

    # -- auth changes --------------------------------------------------------
    op.create_table('tidb_auth_changes',
        sa.Column('subject_type', sa.String(length=32), nullable=False, server_default='surface'),
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
    op.create_index(op.f('ix_tidb_auth_changes_subject'), 'tidb_auth_changes', ['subject'], unique=False)
    op.create_index('ix_tidb_auth_changes_subject_type', 'tidb_auth_changes', ['subject_type', 'subject'], unique=False)
    op.create_index(op.f('ix_tidb_auth_changes_mission_id'), 'tidb_auth_changes', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_auth_changes_correlation_id'), 'tidb_auth_changes', ['correlation_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_auth_changes_correlation_id'), table_name='tidb_auth_changes')
    op.drop_index(op.f('ix_tidb_auth_changes_mission_id'), table_name='tidb_auth_changes')
    op.drop_index('ix_tidb_auth_changes_subject_type', table_name='tidb_auth_changes')
    op.drop_index(op.f('ix_tidb_auth_changes_subject'), table_name='tidb_auth_changes')
    op.drop_table('tidb_auth_changes')

    op.drop_index(op.f('ix_tidb_auth_evidence_mission_id'), table_name='tidb_auth_evidence')
    op.drop_index(op.f('ix_tidb_auth_evidence_correlation_id'), table_name='tidb_auth_evidence')
    op.drop_index('ix_tidb_auth_evidence_subject', table_name='tidb_auth_evidence')
    op.drop_index(op.f('ix_tidb_auth_evidence_subject_id'), table_name='tidb_auth_evidence')
    op.drop_index(op.f('ix_tidb_auth_evidence_subject_type'), table_name='tidb_auth_evidence')
    op.drop_table('tidb_auth_evidence')

    op.drop_index(op.f('ix_tidb_auth_observations_mission_id'), table_name='tidb_auth_observations')
    op.drop_index(op.f('ix_tidb_auth_observations_correlation_id'), table_name='tidb_auth_observations')
    op.drop_index(op.f('ix_tidb_auth_observations_target_key'), table_name='tidb_auth_observations')
    op.drop_index('ix_tidb_auth_observations_origin_kind', table_name='tidb_auth_observations')
    op.drop_index(op.f('ix_tidb_auth_observations_name'), table_name='tidb_auth_observations')
    op.drop_index(op.f('ix_tidb_auth_observations_kind'), table_name='tidb_auth_observations')
    op.drop_index(op.f('ix_tidb_auth_observations_origin'), table_name='tidb_auth_observations')
    op.drop_table('tidb_auth_observations')

    op.drop_index(op.f('ix_tidb_tenant_indicators_mission_id'), table_name='tidb_tenant_indicators')
    op.drop_index(op.f('ix_tidb_tenant_indicators_correlation_id'), table_name='tidb_tenant_indicators')
    op.drop_index(op.f('ix_tidb_tenant_indicators_target_key'), table_name='tidb_tenant_indicators')
    op.drop_index(op.f('ix_tidb_tenant_indicators_api_id'), table_name='tidb_tenant_indicators')
    op.drop_index(op.f('ix_tidb_tenant_indicators_tenant_type'), table_name='tidb_tenant_indicators')
    op.drop_index(op.f('ix_tidb_tenant_indicators_name'), table_name='tidb_tenant_indicators')
    op.drop_index(op.f('ix_tidb_tenant_indicators_origin'), table_name='tidb_tenant_indicators')
    op.drop_table('tidb_tenant_indicators')

    op.drop_index(op.f('ix_tidb_permission_indicators_mission_id'), table_name='tidb_permission_indicators')
    op.drop_index(op.f('ix_tidb_permission_indicators_correlation_id'), table_name='tidb_permission_indicators')
    op.drop_index(op.f('ix_tidb_permission_indicators_target_key'), table_name='tidb_permission_indicators')
    op.drop_index(op.f('ix_tidb_permission_indicators_name'), table_name='tidb_permission_indicators')
    op.drop_index(op.f('ix_tidb_permission_indicators_origin'), table_name='tidb_permission_indicators')
    op.drop_table('tidb_permission_indicators')

    op.drop_index(op.f('ix_tidb_scope_indicators_mission_id'), table_name='tidb_scope_indicators')
    op.drop_index(op.f('ix_tidb_scope_indicators_correlation_id'), table_name='tidb_scope_indicators')
    op.drop_index(op.f('ix_tidb_scope_indicators_target_key'), table_name='tidb_scope_indicators')
    op.drop_index(op.f('ix_tidb_scope_indicators_name'), table_name='tidb_scope_indicators')
    op.drop_index(op.f('ix_tidb_scope_indicators_origin'), table_name='tidb_scope_indicators')
    op.drop_table('tidb_scope_indicators')

    op.drop_index(op.f('ix_tidb_role_indicators_mission_id'), table_name='tidb_role_indicators')
    op.drop_index(op.f('ix_tidb_role_indicators_correlation_id'), table_name='tidb_role_indicators')
    op.drop_index(op.f('ix_tidb_role_indicators_target_key'), table_name='tidb_role_indicators')
    op.drop_index(op.f('ix_tidb_role_indicators_name'), table_name='tidb_role_indicators')
    op.drop_index(op.f('ix_tidb_role_indicators_origin'), table_name='tidb_role_indicators')
    op.drop_table('tidb_role_indicators')

    op.drop_index(op.f('ix_tidb_webauthn_indicators_mission_id'), table_name='tidb_webauthn_indicators')
    op.drop_index(op.f('ix_tidb_webauthn_indicators_correlation_id'), table_name='tidb_webauthn_indicators')
    op.drop_index(op.f('ix_tidb_webauthn_indicators_target_key'), table_name='tidb_webauthn_indicators')
    op.drop_index(op.f('ix_tidb_webauthn_indicators_kind'), table_name='tidb_webauthn_indicators')
    op.drop_index(op.f('ix_tidb_webauthn_indicators_origin'), table_name='tidb_webauthn_indicators')
    op.drop_table('tidb_webauthn_indicators')

    op.drop_index(op.f('ix_tidb_mfa_mechanisms_mission_id'), table_name='tidb_mfa_mechanisms')
    op.drop_index(op.f('ix_tidb_mfa_mechanisms_correlation_id'), table_name='tidb_mfa_mechanisms')
    op.drop_index(op.f('ix_tidb_mfa_mechanisms_target_key'), table_name='tidb_mfa_mechanisms')
    op.drop_index(op.f('ix_tidb_mfa_mechanisms_kind'), table_name='tidb_mfa_mechanisms')
    op.drop_index(op.f('ix_tidb_mfa_mechanisms_origin'), table_name='tidb_mfa_mechanisms')
    op.drop_table('tidb_mfa_mechanisms')

    op.drop_index(op.f('ix_tidb_cors_policies_mission_id'), table_name='tidb_cors_policies')
    op.drop_index(op.f('ix_tidb_cors_policies_correlation_id'), table_name='tidb_cors_policies')
    op.drop_index(op.f('ix_tidb_cors_policies_target_key'), table_name='tidb_cors_policies')
    op.drop_index(op.f('ix_tidb_cors_policies_origin'), table_name='tidb_cors_policies')
    op.drop_table('tidb_cors_policies')

    op.drop_index(op.f('ix_tidb_csrf_mechanisms_mission_id'), table_name='tidb_csrf_mechanisms')
    op.drop_index(op.f('ix_tidb_csrf_mechanisms_correlation_id'), table_name='tidb_csrf_mechanisms')
    op.drop_index(op.f('ix_tidb_csrf_mechanisms_target_key'), table_name='tidb_csrf_mechanisms')
    op.drop_index(op.f('ix_tidb_csrf_mechanisms_kind'), table_name='tidb_csrf_mechanisms')
    op.drop_index(op.f('ix_tidb_csrf_mechanisms_origin'), table_name='tidb_csrf_mechanisms')
    op.drop_table('tidb_csrf_mechanisms')

    op.drop_index(op.f('ix_tidb_token_storage_indicators_mission_id'), table_name='tidb_token_storage_indicators')
    op.drop_index(op.f('ix_tidb_token_storage_indicators_correlation_id'), table_name='tidb_token_storage_indicators')
    op.drop_index(op.f('ix_tidb_token_storage_indicators_target_key'), table_name='tidb_token_storage_indicators')
    op.drop_index(op.f('ix_tidb_token_storage_indicators_token_category'), table_name='tidb_token_storage_indicators')
    op.drop_index(op.f('ix_tidb_token_storage_indicators_storage_type'), table_name='tidb_token_storage_indicators')
    op.drop_index(op.f('ix_tidb_token_storage_indicators_origin'), table_name='tidb_token_storage_indicators')
    op.drop_table('tidb_token_storage_indicators')

    op.drop_index(op.f('ix_tidb_auth_cookies_mission_id'), table_name='tidb_auth_cookies')
    op.drop_index(op.f('ix_tidb_auth_cookies_correlation_id'), table_name='tidb_auth_cookies')
    op.drop_index(op.f('ix_tidb_auth_cookies_target_key'), table_name='tidb_auth_cookies')
    op.drop_index('ix_tidb_auth_cookies_name_origin', table_name='tidb_auth_cookies')
    op.drop_index(op.f('ix_tidb_auth_cookies_origin'), table_name='tidb_auth_cookies')
    op.drop_index(op.f('ix_tidb_auth_cookies_name'), table_name='tidb_auth_cookies')
    op.drop_table('tidb_auth_cookies')

    op.drop_index(op.f('ix_tidb_auth_schemes_mission_id'), table_name='tidb_auth_schemes')
    op.drop_index(op.f('ix_tidb_auth_schemes_correlation_id'), table_name='tidb_auth_schemes')
    op.drop_index(op.f('ix_tidb_auth_schemes_target_key'), table_name='tidb_auth_schemes')
    op.drop_index('ix_tidb_auth_schemes_origin_type', table_name='tidb_auth_schemes')
    op.drop_index(op.f('ix_tidb_auth_schemes_scheme_type'), table_name='tidb_auth_schemes')
    op.drop_index(op.f('ix_tidb_auth_schemes_api_id'), table_name='tidb_auth_schemes')
    op.drop_index(op.f('ix_tidb_auth_schemes_origin'), table_name='tidb_auth_schemes')
    op.drop_table('tidb_auth_schemes')

    op.drop_index(op.f('ix_tidb_saml_configs_mission_id'), table_name='tidb_saml_configs')
    op.drop_index(op.f('ix_tidb_saml_configs_correlation_id'), table_name='tidb_saml_configs')
    op.drop_index(op.f('ix_tidb_saml_configs_target_key'), table_name='tidb_saml_configs')
    op.drop_index(op.f('ix_tidb_saml_configs_origin'), table_name='tidb_saml_configs')
    op.drop_table('tidb_saml_configs')

    op.drop_index(op.f('ix_tidb_oidc_configs_mission_id'), table_name='tidb_oidc_configs')
    op.drop_index(op.f('ix_tidb_oidc_configs_correlation_id'), table_name='tidb_oidc_configs')
    op.drop_index(op.f('ix_tidb_oidc_configs_target_key'), table_name='tidb_oidc_configs')
    op.drop_index(op.f('ix_tidb_oidc_configs_origin'), table_name='tidb_oidc_configs')
    op.drop_table('tidb_oidc_configs')

    op.drop_index(op.f('ix_tidb_oauth_configs_mission_id'), table_name='tidb_oauth_configs')
    op.drop_index(op.f('ix_tidb_oauth_configs_correlation_id'), table_name='tidb_oauth_configs')
    op.drop_index(op.f('ix_tidb_oauth_configs_target_key'), table_name='tidb_oauth_configs')
    op.drop_index(op.f('ix_tidb_oauth_configs_origin'), table_name='tidb_oauth_configs')
    op.drop_table('tidb_oauth_configs')

    op.drop_index(op.f('ix_tidb_identity_providers_mission_id'), table_name='tidb_identity_providers')
    op.drop_index(op.f('ix_tidb_identity_providers_correlation_id'), table_name='tidb_identity_providers')
    op.drop_index(op.f('ix_tidb_identity_providers_target_key'), table_name='tidb_identity_providers')
    op.drop_index(op.f('ix_tidb_identity_providers_origin'), table_name='tidb_identity_providers')
    op.drop_index(op.f('ix_tidb_identity_providers_provider_kind'), table_name='tidb_identity_providers')
    op.drop_index(op.f('ix_tidb_identity_providers_name'), table_name='tidb_identity_providers')
    op.drop_table('tidb_identity_providers')

    op.drop_index(op.f('ix_tidb_auth_flows_mission_id'), table_name='tidb_auth_flows')
    op.drop_index(op.f('ix_tidb_auth_flows_correlation_id'), table_name='tidb_auth_flows')
    op.drop_index(op.f('ix_tidb_auth_flows_target_key'), table_name='tidb_auth_flows')
    op.drop_index(op.f('ix_tidb_auth_flows_origin'), table_name='tidb_auth_flows')
    op.drop_index(op.f('ix_tidb_auth_flows_flow_kind'), table_name='tidb_auth_flows')
    op.drop_index(op.f('ix_tidb_auth_flows_name'), table_name='tidb_auth_flows')
    op.drop_table('tidb_auth_flows')

    op.drop_index(op.f('ix_tidb_auth_endpoints_mission_id'), table_name='tidb_auth_endpoints')
    op.drop_index(op.f('ix_tidb_auth_endpoints_correlation_id'), table_name='tidb_auth_endpoints')
    op.drop_index(op.f('ix_tidb_auth_endpoints_target_key'), table_name='tidb_auth_endpoints')
    op.drop_index('ix_tidb_auth_endpoints_url_kind', table_name='tidb_auth_endpoints')
    op.drop_index(op.f('ix_tidb_auth_endpoints_api_id'), table_name='tidb_auth_endpoints')
    op.drop_index(op.f('ix_tidb_auth_endpoints_kind'), table_name='tidb_auth_endpoints')
    op.drop_index(op.f('ix_tidb_auth_endpoints_origin'), table_name='tidb_auth_endpoints')
    op.drop_index(op.f('ix_tidb_auth_endpoints_url'), table_name='tidb_auth_endpoints')
    op.drop_table('tidb_auth_endpoints')

    op.drop_index(op.f('ix_tidb_auth_surfaces_mission_id'), table_name='tidb_auth_surfaces')
    op.drop_index(op.f('ix_tidb_auth_surfaces_correlation_id'), table_name='tidb_auth_surfaces')
    op.drop_index(op.f('ix_tidb_auth_surfaces_target_key'), table_name='tidb_auth_surfaces')
    op.drop_index(op.f('ix_tidb_auth_surfaces_access_state'), table_name='tidb_auth_surfaces')
    op.drop_index(op.f('ix_tidb_auth_surfaces_surface_kind'), table_name='tidb_auth_surfaces')
    op.drop_index(op.f('ix_tidb_auth_surfaces_origin'), table_name='tidb_auth_surfaces')
    op.drop_index(op.f('ix_tidb_auth_surfaces_url'), table_name='tidb_auth_surfaces')
    op.drop_table('tidb_auth_surfaces')

    op.drop_index(op.f('ix_tidb_auth_runs_correlation_id'), table_name='tidb_auth_runs')
    op.drop_index(op.f('ix_tidb_auth_runs_target_key'), table_name='tidb_auth_runs')
    op.drop_index(op.f('ix_tidb_auth_runs_mission_id'), table_name='tidb_auth_runs')
    op.drop_table('tidb_auth_runs')
