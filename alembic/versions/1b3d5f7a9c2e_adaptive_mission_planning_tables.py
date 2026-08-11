"""adaptive mission planning tables

Sprint 027. Creates the normalized Adaptive Mission & Attack-Path Planning
entities: missions, action nodes, dynamic dependencies, conditional branches,
plan versions, plan deltas, decisions, attack paths, gaps, checkpoints,
failures, tool fallbacks and tool selections.

Revision ID: 1b3d5f7a9c2e
Revises: f7aed8a3dfc0
Create Date: 2026-08-10 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '1b3d5f7a9c2e'
down_revision: str | Sequence[str] | None = 'f7aed8a3dfc0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _envelope() -> list[sa.Column]:
    """Return the shared TIDB envelope columns."""
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


def _create(name: str, columns: list[sa.Column], indexes: list[tuple[str, str, list[str], bool]] | None = None) -> None:
    op.create_table(name, *(columns + _envelope()) + [sa.PrimaryKeyConstraint('id')])
    for index_name, table, cols, unique in indexes or ():
        op.create_index(index_name, table, cols, unique=unique)


def upgrade() -> None:
    """Upgrade schema."""
    _create('tidb_adaptive_missions', [
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('objective', sa.String(length=64), nullable=False),
        sa.Column('mode', sa.String(length=32), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('plan_version', sa.Integer(), nullable=False),
        sa.Column('progress', sa.Float(), nullable=False),
        sa.Column('authorization_context', sa.String(length=64), nullable=False),
        sa.Column('safety_ceiling', sa.String(length=64), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_adaptive_missions_mission_id', 'tidb_adaptive_missions', ['mission_id'], False),
        ('ix_tidb_adaptive_missions_state', 'tidb_adaptive_missions', ['state'], False),
        ('ix_tidb_adaptive_missions_tenant', 'tidb_adaptive_missions', ['tenant'], False),
        ('ix_tidb_adaptive_mission_scope', 'tidb_adaptive_missions', ['tenant', 'mission_id'], False),
    ])

    _create('tidb_adaptive_action_nodes', [
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('asset', sa.Text(), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('selected_tool', sa.String(length=128), nullable=False),
        sa.Column('tool_candidates', sa.JSON(), nullable=False),
        sa.Column('hypothesis_id', sa.String(length=64), nullable=False),
        sa.Column('expected_information_gain', sa.Float(), nullable=False),
        sa.Column('expected_proof_value', sa.Float(), nullable=False),
        sa.Column('risk', sa.Float(), nullable=False),
        sa.Column('cost', sa.Float(), nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), nullable=False),
        sa.Column('validation_level', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
        sa.Column('depends_on', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_adaptive_action_nodes_action_id', 'tidb_adaptive_action_nodes', ['action_id'], False),
        ('ix_tidb_adaptive_action_nodes_mission_id', 'tidb_adaptive_action_nodes', ['mission_id'], False),
        ('ix_tidb_adaptive_action_nodes_capability', 'tidb_adaptive_action_nodes', ['capability'], False),
        ('ix_tidb_adaptive_action_nodes_hypothesis_id', 'tidb_adaptive_action_nodes', ['hypothesis_id'], False),
        ('ix_tidb_adaptive_action_nodes_status', 'tidb_adaptive_action_nodes', ['status'], False),
        ('ix_tidb_adaptive_action_mission_status', 'tidb_adaptive_action_nodes', ['mission_id', 'status'], False),
        ('ix_tidb_adaptive_action_mission_cap', 'tidb_adaptive_action_nodes', ['mission_id', 'capability'], False),
    ])

    _create('tidb_adaptive_dependencies', [
        sa.Column('dependency_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('source_action_id', sa.String(length=26), nullable=False),
        sa.Column('target_action_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_adaptive_dependencies_dependency_id', 'tidb_adaptive_dependencies', ['dependency_id'], False),
        ('ix_tidb_adaptive_dependencies_mission_id', 'tidb_adaptive_dependencies', ['mission_id'], False),
        ('ix_tidb_adaptive_dependencies_source_action_id', 'tidb_adaptive_dependencies', ['source_action_id'], False),
        ('ix_tidb_adaptive_dependencies_target_action_id', 'tidb_adaptive_dependencies', ['target_action_id'], False),
        ('ix_tidb_adaptive_dep_mission_src', 'tidb_adaptive_dependencies', ['mission_id', 'source_action_id'], False),
    ])

    _create('tidb_adaptive_branches', [
        sa.Column('branch_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('condition', sa.Text(), nullable=False),
        sa.Column('then_action_ids', sa.JSON(), nullable=False),
        sa.Column('else_action_ids', sa.JSON(), nullable=False),
        sa.Column('goto_action_id', sa.String(length=26), nullable=False),
        sa.Column('wait_for_evidence', sa.Text(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_adaptive_branches_branch_id', 'tidb_adaptive_branches', ['branch_id'], False),
        ('ix_tidb_adaptive_branches_mission_id', 'tidb_adaptive_branches', ['mission_id'], False),
    ])

    _create('tidb_adaptive_plan_versions', [
        sa.Column('version_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_version', sa.Integer(), nullable=False),
        sa.Column('parent_version', sa.Integer(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('trigger', sa.String(length=64), nullable=False),
        sa.Column('changed_nodes', sa.JSON(), nullable=False),
        sa.Column('changed_dependencies', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.String(length=64), nullable=False),
        sa.Column('decision_provenance', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_adaptive_plan_versions_version_id', 'tidb_adaptive_plan_versions', ['version_id'], False),
        ('ix_tidb_adaptive_plan_versions_mission_id', 'tidb_adaptive_plan_versions', ['mission_id'], False),
        ('ix_tidb_adaptive_version_mission_version', 'tidb_adaptive_plan_versions', ['mission_id', 'plan_version'], False),
    ])

    _create('tidb_adaptive_plan_deltas', [
        sa.Column('delta_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_version', sa.Integer(), nullable=False),
        sa.Column('parent_version', sa.Integer(), nullable=False),
        sa.Column('trigger', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('changes', sa.JSON(), nullable=False),
        sa.Column('decision_provenance', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_adaptive_plan_deltas_delta_id', 'tidb_adaptive_plan_deltas', ['delta_id'], False),
        ('ix_tidb_adaptive_plan_deltas_mission_id', 'tidb_adaptive_plan_deltas', ['mission_id'], False),
        ('ix_tidb_adaptive_delta_mission_version', 'tidb_adaptive_plan_deltas', ['mission_id', 'plan_version'], False),
    ])

    _create('tidb_adaptive_decisions', [
        sa.Column('decision_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('why_this_action', sa.Text(), nullable=False),
        sa.Column('why_now', sa.Text(), nullable=False),
        sa.Column('why_this_tool', sa.Text(), nullable=False),
        sa.Column('information_provided', sa.Text(), nullable=False),
        sa.Column('hypothesis_tested', sa.String(length=64), nullable=False),
        sa.Column('evidence_expected', sa.Text(), nullable=False),
        sa.Column('proof_enabled', sa.Text(), nullable=False),
        sa.Column('alternatives', sa.JSON(), nullable=False),
        sa.Column('decision_provenance', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_adaptive_decisions_decision_id', 'tidb_adaptive_decisions', ['decision_id'], False),
        ('ix_tidb_adaptive_decisions_mission_id', 'tidb_adaptive_decisions', ['mission_id'], False),
        ('ix_tidb_adaptive_decisions_action_id', 'tidb_adaptive_decisions', ['action_id'], False),
    ])

    _create('tidb_adaptive_attack_paths', [
        sa.Column('path_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('objective', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('scores', sa.JSON(), nullable=False),
        sa.Column('steps', sa.JSON(), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('assumptions', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_adaptive_attack_paths_path_id', 'tidb_adaptive_attack_paths', ['path_id'], False),
        ('ix_tidb_adaptive_attack_paths_mission_id', 'tidb_adaptive_attack_paths', ['mission_id'], False),
        ('ix_tidb_adaptive_attack_paths_state', 'tidb_adaptive_attack_paths', ['state'], False),
    ])

    _create('tidb_adaptive_gaps', [
        sa.Column('gap_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('finding_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('asset_key', sa.Text(), nullable=False),
        sa.Column('required_evidence', sa.JSON(), nullable=False),
        sa.Column('minimum_action', sa.Text(), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
    ], [
        ('ix_tidb_adaptive_gaps_gap_id', 'tidb_adaptive_gaps', ['gap_id'], False),
        ('ix_tidb_adaptive_gaps_mission_id', 'tidb_adaptive_gaps', ['mission_id'], False),
        ('ix_tidb_adaptive_gaps_finding_id', 'tidb_adaptive_gaps', ['finding_id'], False),
    ])

    _create('tidb_adaptive_checkpoints', [
        sa.Column('checkpoint_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_version', sa.Integer(), nullable=False),
        sa.Column('mission_state', sa.String(length=32), nullable=False),
        sa.Column('completed_actions', sa.JSON(), nullable=False),
        sa.Column('pending_actions', sa.JSON(), nullable=False),
        sa.Column('observations', sa.JSON(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('hypotheses', sa.JSON(), nullable=False),
        sa.Column('proof_states', sa.JSON(), nullable=False),
        sa.Column('tool_state', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_adaptive_checkpoints_checkpoint_id', 'tidb_adaptive_checkpoints', ['checkpoint_id'], False),
        ('ix_tidb_adaptive_checkpoints_mission_id', 'tidb_adaptive_checkpoints', ['mission_id'], False),
    ])

    _create('tidb_adaptive_failures', [
        sa.Column('failure_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('failure_class', sa.String(length=32), nullable=False),
        sa.Column('management', sa.String(length=32), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
        sa.Column('retries', sa.Integer(), nullable=False),
    ], [
        ('ix_tidb_adaptive_failures_failure_id', 'tidb_adaptive_failures', ['failure_id'], False),
        ('ix_tidb_adaptive_failures_mission_id', 'tidb_adaptive_failures', ['mission_id'], False),
        ('ix_tidb_adaptive_failures_action_id', 'tidb_adaptive_failures', ['action_id'], False),
    ])

    _create('tidb_adaptive_tool_fallbacks', [
        sa.Column('fallback_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('primary_tool', sa.String(length=128), nullable=False),
        sa.Column('fallback_tool', sa.String(length=128), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_adaptive_tool_fallbacks_fallback_id', 'tidb_adaptive_tool_fallbacks', ['fallback_id'], False),
        ('ix_tidb_adaptive_tool_fallbacks_mission_id', 'tidb_adaptive_tool_fallbacks', ['mission_id'], False),
        ('ix_tidb_adaptive_tool_fallbacks_action_id', 'tidb_adaptive_tool_fallbacks', ['action_id'], False),
    ])

    _create('tidb_adaptive_tool_selections', [
        sa.Column('selection_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('alternatives', sa.JSON(), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('reasons', sa.JSON(), nullable=False),
        sa.Column('expected_evidence', sa.JSON(), nullable=False),
        sa.Column('expected_proof_value', sa.Float(), nullable=False),
        sa.Column('risk', sa.Float(), nullable=False),
        sa.Column('cost', sa.Float(), nullable=False),
    ], [
        ('ix_tidb_adaptive_tool_selections_selection_id', 'tidb_adaptive_tool_selections', ['selection_id'], False),
        ('ix_tidb_adaptive_tool_selections_mission_id', 'tidb_adaptive_tool_selections', ['mission_id'], False),
        ('ix_tidb_adaptive_tool_selections_action_id', 'tidb_adaptive_tool_selections', ['action_id'], False),
        ('ix_tidb_adaptive_tool_selections_capability', 'tidb_adaptive_tool_selections', ['capability'], False),
        ('ix_tidb_adaptive_tool_selections_tool_id', 'tidb_adaptive_tool_selections', ['tool_id'], False),
    ])


def downgrade() -> None:
    """Downgrade schema."""
    for name in [
        'tidb_adaptive_tool_selections',
        'tidb_adaptive_tool_fallbacks',
        'tidb_adaptive_failures',
        'tidb_adaptive_checkpoints',
        'tidb_adaptive_gaps',
        'tidb_adaptive_attack_paths',
        'tidb_adaptive_decisions',
        'tidb_adaptive_plan_deltas',
        'tidb_adaptive_plan_versions',
        'tidb_adaptive_branches',
        'tidb_adaptive_dependencies',
        'tidb_adaptive_action_nodes',
        'tidb_adaptive_missions',
    ]:
        op.drop_table(name)
