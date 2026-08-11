"""web crawling intelligence tables

Revision ID: 9c2a1b7d3f5e
Revises: 7ab1a304e8bb
Create Date: 2026-08-09 10:00:00.000000

Extends the TIDB web-layer schema (created in the baseline, extended by the
technology intelligence migration) with the crawl-specific projections of the
web crawling & web attack-surface discovery capability: web origins, URL
observations, redirects, API/WebSocket/GraphQL endpoints, authentication
boundaries, crawl run records and crawl evidence.

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9c2a1b7d3f5e'
down_revision: str | Sequence[str] | None = '7ab1a304e8bb'
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


def upgrade() -> None:
    """Upgrade schema."""
    # -- web origins ---------------------------------------------------------
    op.create_table('tidb_web_origins',
        sa.Column('scheme', sa.String(length=16), nullable=False),
        sa.Column('host', sa.String(length=255), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('target_id', sa.String(length=26), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('is_upgrade_candidate', sa.Boolean(), nullable=False),
        sa.Column('key', sa.String(length=512), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_web_origins_host'), 'tidb_web_origins', ['host'], unique=False)
    op.create_index(op.f('ix_tidb_web_origins_key'), 'tidb_web_origins', ['key'], unique=False)
    op.create_index(op.f('ix_tidb_web_origins_target_id'), 'tidb_web_origins', ['target_id'], unique=False)

    # -- URL observations ----------------------------------------------------
    op.create_table('tidb_url_observations',
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('origin_id', sa.String(length=26), nullable=True),
        sa.Column('path', sa.Text(), nullable=False),
        sa.Column('query', sa.Text(), nullable=True),
        sa.Column('status_code', sa.Integer(), nullable=True),
        sa.Column('content_type', sa.String(length=128), nullable=True),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        sa.Column('execution_id', sa.String(length=26), nullable=True),
        sa.Column('times_seen', sa.Integer(), nullable=False),
        sa.Column('key', sa.String(length=1024), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['origin_id'], ['tidb_web_origins.id'], ),
    )
    op.create_index(op.f('ix_tidb_url_observations_url'), 'tidb_url_observations', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_origin_id'), 'tidb_url_observations', ['origin_id'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_target_id'), 'tidb_url_observations', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_target_key'), 'tidb_url_observations', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_correlation_id'), 'tidb_url_observations', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_mission_id'), 'tidb_url_observations', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_execution_id'), 'tidb_url_observations', ['execution_id'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_tool_id'), 'tidb_url_observations', ['tool_id'], unique=False)
    op.create_index(op.f('ix_tidb_url_observations_key'), 'tidb_url_observations', ['key'], unique=False)

    # -- redirects -----------------------------------------------------------
    op.create_table('tidb_web_redirects',
        sa.Column('source_url', sa.Text(), nullable=False),
        sa.Column('destination_url', sa.Text(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('redirect_type', sa.String(length=32), nullable=False),
        sa.Column('chain', sa.JSON(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_web_redirects_target_key'), 'tidb_web_redirects', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_web_redirects_correlation_id'), 'tidb_web_redirects', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_web_redirects_mission_id'), 'tidb_web_redirects', ['mission_id'], unique=False)

    # -- API endpoints -------------------------------------------------------
    op.create_table('tidb_web_api_endpoints',
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('content_type', sa.String(length=128), nullable=True),
        sa.Column('response_content_type', sa.String(length=128), nullable=True),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_web_api_endpoints_url'), 'tidb_web_api_endpoints', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_web_api_endpoints_target_key'), 'tidb_web_api_endpoints', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_web_api_endpoints_correlation_id'), 'tidb_web_api_endpoints', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_web_api_endpoints_mission_id'), 'tidb_web_api_endpoints', ['mission_id'], unique=False)

    # -- WebSocket endpoints -------------------------------------------------
    op.create_table('tidb_web_websocket_endpoints',
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('protocol', sa.String(length=16), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_web_websocket_endpoints_url'), 'tidb_web_websocket_endpoints', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_web_websocket_endpoints_target_key'), 'tidb_web_websocket_endpoints', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_web_websocket_endpoints_correlation_id'), 'tidb_web_websocket_endpoints', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_web_websocket_endpoints_mission_id'), 'tidb_web_websocket_endpoints', ['mission_id'], unique=False)

    # -- GraphQL endpoints ---------------------------------------------------
    op.create_table('tidb_web_graphql_endpoints',
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('methods', sa.JSON(), nullable=False),
        sa.Column('introspection', sa.String(length=16), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_web_graphql_endpoints_url'), 'tidb_web_graphql_endpoints', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_web_graphql_endpoints_target_key'), 'tidb_web_graphql_endpoints', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_web_graphql_endpoints_correlation_id'), 'tidb_web_graphql_endpoints', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_web_graphql_endpoints_mission_id'), 'tidb_web_graphql_endpoints', ['mission_id'], unique=False)

    # -- authentication boundaries -------------------------------------------
    op.create_table('tidb_web_auth_boundaries',
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('scheme', sa.String(length=32), nullable=False),
        sa.Column('indicators', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_web_auth_boundaries_url'), 'tidb_web_auth_boundaries', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_web_auth_boundaries_target_key'), 'tidb_web_auth_boundaries', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_web_auth_boundaries_correlation_id'), 'tidb_web_auth_boundaries', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_web_auth_boundaries_mission_id'), 'tidb_web_auth_boundaries', ['mission_id'], unique=False)

    # -- crawl executions ----------------------------------------------------
    op.create_table('tidb_crawl_executions',
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=True),
        sa.Column('mode', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('urls_seen', sa.Integer(), nullable=False),
        sa.Column('urls_distinct', sa.Integer(), nullable=False),
        sa.Column('endpoints', sa.Integer(), nullable=False),
        sa.Column('redirects', sa.Integer(), nullable=False),
        sa.Column('websockets', sa.Integer(), nullable=False),
        sa.Column('graphqls', sa.Integer(), nullable=False),
        sa.Column('auth_boundaries', sa.Integer(), nullable=False),
        sa.Column('policy', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=True),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        sa.Column('summary', sa.JSON(), nullable=False),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_crawl_executions_mission_id'), 'tidb_crawl_executions', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_executions_target_key'), 'tidb_crawl_executions', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_executions_target_id'), 'tidb_crawl_executions', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_executions_status'), 'tidb_crawl_executions', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_executions_correlation_id'), 'tidb_crawl_executions', ['correlation_id'], unique=False)

    # -- crawl evidence ------------------------------------------------------
    op.create_table('tidb_crawl_evidence',
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('evidence_type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=64), nullable=True),
        sa.Column('integrity', sa.String(length=64), nullable=True),
        sa.Column('target_key', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=26), nullable=True),
        sa.Column('mission_id', sa.String(length=26), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_crawl_evidence_url'), 'tidb_crawl_evidence', ['url'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_evidence_evidence_type'), 'tidb_crawl_evidence', ['evidence_type'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_evidence_integrity'), 'tidb_crawl_evidence', ['integrity'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_evidence_target_key'), 'tidb_crawl_evidence', ['target_key'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_evidence_correlation_id'), 'tidb_crawl_evidence', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_crawl_evidence_mission_id'), 'tidb_crawl_evidence', ['mission_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_crawl_evidence_mission_id'), table_name='tidb_crawl_evidence')
    op.drop_index(op.f('ix_tidb_crawl_evidence_correlation_id'), table_name='tidb_crawl_evidence')
    op.drop_index(op.f('ix_tidb_crawl_evidence_target_key'), table_name='tidb_crawl_evidence')
    op.drop_index(op.f('ix_tidb_crawl_evidence_integrity'), table_name='tidb_crawl_evidence')
    op.drop_index(op.f('ix_tidb_crawl_evidence_evidence_type'), table_name='tidb_crawl_evidence')
    op.drop_index(op.f('ix_tidb_crawl_evidence_url'), table_name='tidb_crawl_evidence')
    op.drop_table('tidb_crawl_evidence')

    op.drop_index(op.f('ix_tidb_crawl_executions_correlation_id'), table_name='tidb_crawl_executions')
    op.drop_index(op.f('ix_tidb_crawl_executions_status'), table_name='tidb_crawl_executions')
    op.drop_index(op.f('ix_tidb_crawl_executions_target_id'), table_name='tidb_crawl_executions')
    op.drop_index(op.f('ix_tidb_crawl_executions_target_key'), table_name='tidb_crawl_executions')
    op.drop_index(op.f('ix_tidb_crawl_executions_mission_id'), table_name='tidb_crawl_executions')
    op.drop_table('tidb_crawl_executions')

    op.drop_index(op.f('ix_tidb_web_auth_boundaries_mission_id'), table_name='tidb_web_auth_boundaries')
    op.drop_index(op.f('ix_tidb_web_auth_boundaries_correlation_id'), table_name='tidb_web_auth_boundaries')
    op.drop_index(op.f('ix_tidb_web_auth_boundaries_target_key'), table_name='tidb_web_auth_boundaries')
    op.drop_index(op.f('ix_tidb_web_auth_boundaries_url'), table_name='tidb_web_auth_boundaries')
    op.drop_table('tidb_web_auth_boundaries')

    op.drop_index(op.f('ix_tidb_web_graphql_endpoints_mission_id'), table_name='tidb_web_graphql_endpoints')
    op.drop_index(op.f('ix_tidb_web_graphql_endpoints_correlation_id'), table_name='tidb_web_graphql_endpoints')
    op.drop_index(op.f('ix_tidb_web_graphql_endpoints_target_key'), table_name='tidb_web_graphql_endpoints')
    op.drop_index(op.f('ix_tidb_web_graphql_endpoints_url'), table_name='tidb_web_graphql_endpoints')
    op.drop_table('tidb_web_graphql_endpoints')

    op.drop_index(op.f('ix_tidb_web_websocket_endpoints_mission_id'), table_name='tidb_web_websocket_endpoints')
    op.drop_index(op.f('ix_tidb_web_websocket_endpoints_correlation_id'), table_name='tidb_web_websocket_endpoints')
    op.drop_index(op.f('ix_tidb_web_websocket_endpoints_target_key'), table_name='tidb_web_websocket_endpoints')
    op.drop_index(op.f('ix_tidb_web_websocket_endpoints_url'), table_name='tidb_web_websocket_endpoints')
    op.drop_table('tidb_web_websocket_endpoints')

    op.drop_index(op.f('ix_tidb_web_api_endpoints_mission_id'), table_name='tidb_web_api_endpoints')
    op.drop_index(op.f('ix_tidb_web_api_endpoints_correlation_id'), table_name='tidb_web_api_endpoints')
    op.drop_index(op.f('ix_tidb_web_api_endpoints_target_key'), table_name='tidb_web_api_endpoints')
    op.drop_index(op.f('ix_tidb_web_api_endpoints_url'), table_name='tidb_web_api_endpoints')
    op.drop_table('tidb_web_api_endpoints')

    op.drop_index(op.f('ix_tidb_web_redirects_mission_id'), table_name='tidb_web_redirects')
    op.drop_index(op.f('ix_tidb_web_redirects_correlation_id'), table_name='tidb_web_redirects')
    op.drop_index(op.f('ix_tidb_web_redirects_target_key'), table_name='tidb_web_redirects')
    op.drop_table('tidb_web_redirects')

    op.drop_index(op.f('ix_tidb_url_observations_key'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_tool_id'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_execution_id'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_mission_id'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_correlation_id'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_target_key'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_target_id'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_origin_id'), table_name='tidb_url_observations')
    op.drop_index(op.f('ix_tidb_url_observations_url'), table_name='tidb_url_observations')
    op.drop_table('tidb_url_observations')

    op.drop_index(op.f('ix_tidb_web_origins_target_id'), table_name='tidb_web_origins')
    op.drop_index(op.f('ix_tidb_web_origins_key'), table_name='tidb_web_origins')
    op.drop_index(op.f('ix_tidb_web_origins_host'), table_name='tidb_web_origins')
    op.drop_table('tidb_web_origins')
