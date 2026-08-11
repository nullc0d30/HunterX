"""adaptive target intelligence tables

Sprint 026. Creates the normalized Target Intelligence entities: targets,
assets, observations, evidence, history, changes, coverage, gaps, hypotheses,
actions, decisions, negative results, conflicts and scores.

Revision ID: f7aed8a3dfc0
Revises: e1f2a3b4c5d6
Create Date: 2026-08-10 08:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'f7aed8a3dfc0'
down_revision: str | Sequence[str] | None = 'e1f2a3b4c5d6'
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
    _create('tidb_intelligence_targets', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('scope', sa.String(length=512), nullable=False),
        sa.Column('identity', sa.String(length=512), nullable=False),
        sa.Column('classification', sa.String(length=128), nullable=False),
        sa.Column('criticality', sa.String(length=32), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('phase', sa.String(length=32), nullable=False),
        sa.Column('intelligence_state', sa.JSON(), nullable=False),
        sa.Column('coverage_state', sa.JSON(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
    ], [
        ('ix_tidb_intelligence_targets_target_id', 'tidb_intelligence_targets', ['target_id'], False),
        ('ix_tidb_intelligence_targets_mission_id', 'tidb_intelligence_targets', ['mission_id'], False),
        ('ix_tidb_intelligence_targets_kind', 'tidb_intelligence_targets', ['kind'], False),
        ('ix_tidb_intelligence_targets_status', 'tidb_intelligence_targets', ['status'], False),
        ('ix_tidb_intelligence_targets_phase', 'tidb_intelligence_targets', ['phase'], False),
        ('ix_tidb_intelligence_targets_tenant', 'tidb_intelligence_targets', ['tenant'], False),
        ('ix_tidb_intel_target_scope', 'tidb_intelligence_targets', ['tenant', 'mission_id', 'target_id'], False),
    ])

    _create('tidb_intelligence_assets', [
        sa.Column('asset_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('label', sa.Text(), nullable=False),
        sa.Column('properties', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('in_scope', sa.Boolean(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('parent_key', sa.String(length=1024), nullable=False),
        sa.Column('observed_by', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_intelligence_assets_asset_id', 'tidb_intelligence_assets', ['asset_id'], False),
        ('ix_tidb_intelligence_assets_target_id', 'tidb_intelligence_assets', ['target_id'], False),
        ('ix_tidb_intelligence_assets_mission_id', 'tidb_intelligence_assets', ['mission_id'], False),
        ('ix_tidb_intelligence_assets_kind', 'tidb_intelligence_assets', ['kind'], False),
        ('ix_tidb_intelligence_assets_asset_key', 'tidb_intelligence_assets', ['asset_key'], False),
        ('ix_tidb_intel_asset_target_key', 'tidb_intelligence_assets', ['target_id', 'asset_key'], False),
    ])

    _create('tidb_intelligence_observations', [
        sa.Column('observation_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.String(length=32), nullable=False),
        sa.Column('observation_type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('normalized_value', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('scope', sa.String(length=512), nullable=False),
        sa.Column('raw_artifact_ref', sa.String(length=512), nullable=False),
        sa.Column('evidence_ref', sa.String(length=512), nullable=False),
        sa.Column('expires_at', sa.String(length=32), nullable=True),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('dedup_key', sa.String(length=128), nullable=False),
        sa.Column('supersedes', sa.String(length=26), nullable=False),
    ], [
        ('ix_tidb_intelligence_observations_observation_id', 'tidb_intelligence_observations', ['observation_id'], False),
        ('ix_tidb_intelligence_observations_target_id', 'tidb_intelligence_observations', ['target_id'], False),
        ('ix_tidb_intelligence_observations_mission_id', 'tidb_intelligence_observations', ['mission_id'], False),
        ('ix_tidb_intelligence_observations_tool', 'tidb_intelligence_observations', ['tool'], False),
        ('ix_tidb_intelligence_observations_capability', 'tidb_intelligence_observations', ['capability'], False),
        ('ix_tidb_intelligence_observations_timestamp', 'tidb_intelligence_observations', ['timestamp'], False),
        ('ix_tidb_intelligence_observations_observation_type', 'tidb_intelligence_observations', ['observation_type'], False),
        ('ix_tidb_intelligence_observations_asset_key', 'tidb_intelligence_observations', ['asset_key'], False),
        ('ix_tidb_intelligence_observations_dedup_key', 'tidb_intelligence_observations', ['dedup_key'], False),
        ('ix_tidb_intel_obs_target_type', 'tidb_intelligence_observations', ['target_id', 'observation_type'], False),
        ('ix_tidb_intel_obs_asset_type', 'tidb_intelligence_observations', ['asset_key', 'observation_type'], False),
    ])

    _create('tidb_intelligence_evidence', [
        sa.Column('evidence_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('what', sa.Text(), nullable=False),
        sa.Column('where', sa.Text(), nullable=False),
        sa.Column('when', sa.String(length=32), nullable=False),
        sa.Column('how', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('why_trust', sa.Text(), nullable=False),
        sa.Column('reproducibility', sa.String(length=32), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('command_configuration', sa.JSON(), nullable=False),
        sa.Column('raw_artifact_ref', sa.String(length=512), nullable=False),
        sa.Column('parser_version', sa.String(length=64), nullable=False),
        sa.Column('normalizer_version', sa.String(length=64), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
    ], [
        ('ix_tidb_intelligence_evidence_evidence_id', 'tidb_intelligence_evidence', ['evidence_id'], False),
        ('ix_tidb_intelligence_evidence_target_id', 'tidb_intelligence_evidence', ['target_id'], False),
        ('ix_tidb_intelligence_evidence_mission_id', 'tidb_intelligence_evidence', ['mission_id'], False),
        ('ix_tidb_intelligence_evidence_asset_key', 'tidb_intelligence_evidence', ['asset_key'], False),
    ])

    _create('tidb_intelligence_history', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('field', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('previous_value', sa.Text(), nullable=False),
        sa.Column('new_value', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('changed_at', sa.String(length=32), nullable=False),
        sa.Column('correlation_id', sa.String(length=26), nullable=False),
    ], [
        ('ix_tidb_intelligence_history_target_id', 'tidb_intelligence_history', ['target_id'], False),
        ('ix_tidb_intelligence_history_mission_id', 'tidb_intelligence_history', ['mission_id'], False),
        ('ix_tidb_intelligence_history_kind', 'tidb_intelligence_history', ['kind'], False),
        ('ix_tidb_intelligence_history_correlation_id', 'tidb_intelligence_history', ['correlation_id'], False),
    ])
    op.create_index('ix_tidb_intelligence_history_asset_key', 'tidb_intelligence_history', ['asset_key'], unique=False)

    _create('tidb_intelligence_changes', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('previous', sa.JSON(), nullable=False),
        sa.Column('current', sa.JSON(), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('detected_at', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_intelligence_changes_target_id', 'tidb_intelligence_changes', ['target_id'], False),
        ('ix_tidb_intelligence_changes_mission_id', 'tidb_intelligence_changes', ['mission_id'], False),
        ('ix_tidb_intelligence_changes_kind', 'tidb_intelligence_changes', ['kind'], False),
    ])
    op.create_index('ix_tidb_intelligence_changes_asset_key', 'tidb_intelligence_changes', ['asset_key'], unique=False)

    _create('tidb_intelligence_coverage', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('tested_at', sa.String(length=32), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_intelligence_coverage_target_id', 'tidb_intelligence_coverage', ['target_id'], False),
        ('ix_tidb_intelligence_coverage_capability', 'tidb_intelligence_coverage', ['capability'], False),
        ('ix_tidb_intelligence_coverage_state', 'tidb_intelligence_coverage', ['state'], False),
        ('ix_tidb_intel_coverage_cell', 'tidb_intelligence_coverage', ['target_id', 'asset_key', 'capability'], False),
    ])
    op.create_index('ix_tidb_intelligence_coverage_asset_key', 'tidb_intelligence_coverage', ['asset_key'], unique=False)

    _create('tidb_intelligence_gaps', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('question', sa.Text(), nullable=False),
        sa.Column('importance', sa.Float(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('required_capability', sa.String(length=64), nullable=False),
        sa.Column('candidate_tools', sa.JSON(), nullable=False),
        sa.Column('estimated_cost', sa.Float(), nullable=False),
        sa.Column('risk', sa.String(length=32), nullable=False),
        sa.Column('blocking', sa.Boolean(), nullable=False),
    ], [
        ('ix_tidb_intelligence_gaps_target_id', 'tidb_intelligence_gaps', ['target_id'], False),
        ('ix_tidb_intelligence_gaps_mission_id', 'tidb_intelligence_gaps', ['mission_id'], False),
        ('ix_tidb_intelligence_gaps_category', 'tidb_intelligence_gaps', ['category'], False),
    ])
    op.create_index('ix_tidb_intelligence_gaps_asset_key', 'tidb_intelligence_gaps', ['asset_key'], unique=False)

    _create('tidb_intelligence_hypotheses', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('category', sa.String(length=48), nullable=False),
        sa.Column('statement', sa.Text(), nullable=False),
        sa.Column('supporting_observations', sa.JSON(), nullable=False),
        sa.Column('contradicting_observations', sa.JSON(), nullable=False),
        sa.Column('required_evidence', sa.JSON(), nullable=False),
        sa.Column('validation_strategy', sa.String(length=128), nullable=False),
        sa.Column('proof_strategy', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
    ], [
        ('ix_tidb_intelligence_hypotheses_target_id', 'tidb_intelligence_hypotheses', ['target_id'], False),
        ('ix_tidb_intelligence_hypotheses_mission_id', 'tidb_intelligence_hypotheses', ['mission_id'], False),
        ('ix_tidb_intelligence_hypotheses_category', 'tidb_intelligence_hypotheses', ['category'], False),
        ('ix_tidb_intelligence_hypotheses_status', 'tidb_intelligence_hypotheses', ['status'], False),
    ])
    op.create_index('ix_tidb_intelligence_hypotheses_asset_key', 'tidb_intelligence_hypotheses', ['asset_key'], unique=False)

    _create('tidb_intelligence_actions', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('objective', sa.Text(), nullable=False),
        sa.Column('action_type', sa.String(length=32), nullable=False),
        sa.Column('required_capability', sa.String(length=64), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expected_information_gain', sa.Float(), nullable=False),
        sa.Column('expected_evidence', sa.JSON(), nullable=False),
        sa.Column('estimated_cost', sa.Float(), nullable=False),
        sa.Column('risk', sa.String(length=32), nullable=False),
        sa.Column('scope_status', sa.String(length=32), nullable=False),
        sa.Column('preconditions', sa.JSON(), nullable=False),
        sa.Column('stop_conditions', sa.JSON(), nullable=False),
        sa.Column('fallback', sa.Text(), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('decision_id', sa.String(length=26), nullable=False),
        sa.Column('candidates', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_intelligence_actions_target_id', 'tidb_intelligence_actions', ['target_id'], False),
        ('ix_tidb_intelligence_actions_mission_id', 'tidb_intelligence_actions', ['mission_id'], False),
        ('ix_tidb_intelligence_actions_action_type', 'tidb_intelligence_actions', ['action_type'], False),
        ('ix_tidb_intelligence_actions_priority', 'tidb_intelligence_actions', ['priority'], False),
        ('ix_tidb_intelligence_actions_status', 'tidb_intelligence_actions', ['status'], False),
        ('ix_tidb_intelligence_actions_decision_id', 'tidb_intelligence_actions', ['decision_id'], False),
    ])
    op.create_index('ix_tidb_intelligence_actions_asset_key', 'tidb_intelligence_actions', ['asset_key'], unique=False)

    _create('tidb_intelligence_decisions', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('rationale', sa.JSON(), nullable=False),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('alternatives', sa.JSON(), nullable=False),
        sa.Column('why_alternatives_rejected', sa.JSON(), nullable=False),
        sa.Column('policy_applied', sa.JSON(), nullable=False),
        sa.Column('ai_assisted', sa.Boolean(), nullable=False),
        sa.Column('ai_overridden', sa.Boolean(), nullable=False),
    ], [
        ('ix_tidb_intelligence_decisions_target_id', 'tidb_intelligence_decisions', ['target_id'], False),
        ('ix_tidb_intelligence_decisions_mission_id', 'tidb_intelligence_decisions', ['mission_id'], False),
        ('ix_tidb_intelligence_decisions_kind', 'tidb_intelligence_decisions', ['kind'], False),
    ])

    _create('tidb_intelligence_negatives', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('tested_capability', sa.String(length=64), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('scope', sa.String(length=512), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('coverage', sa.Text(), nullable=False),
        sa.Column('result', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('tested_at', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_intelligence_negatives_target_id', 'tidb_intelligence_negatives', ['target_id'], False),
        ('ix_tidb_intelligence_negatives_mission_id', 'tidb_intelligence_negatives', ['mission_id'], False),
    ])
    op.create_index('ix_tidb_intelligence_negatives_asset_key', 'tidb_intelligence_negatives', ['asset_key'], unique=False)

    _create('tidb_intelligence_conflicts', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('observations', sa.JSON(), nullable=False),
        sa.Column('tools', sa.JSON(), nullable=False),
        sa.Column('state', sa.String(length=16), nullable=False),
        sa.Column('resolution', sa.Text(), nullable=False),
        sa.Column('detected_at', sa.String(length=32), nullable=False),
        sa.Column('resolved_at', sa.String(length=32), nullable=True),
    ], [
        ('ix_tidb_intelligence_conflicts_target_id', 'tidb_intelligence_conflicts', ['target_id'], False),
        ('ix_tidb_intelligence_conflicts_mission_id', 'tidb_intelligence_conflicts', ['mission_id'], False),
        ('ix_tidb_intelligence_conflicts_state', 'tidb_intelligence_conflicts', ['state'], False),
    ])
    op.create_index('ix_tidb_intelligence_conflicts_asset_key', 'tidb_intelligence_conflicts', ['asset_key'], unique=False)

    _create('tidb_intelligence_scores', [
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('dimensions', sa.JSON(), nullable=False),
        sa.Column('aggregate', sa.Float(), nullable=False),
        sa.Column('weights', sa.JSON(), nullable=False),
        sa.Column('policy_id', sa.String(length=128), nullable=False),
    ], [
        ('ix_tidb_intelligence_scores_target_id', 'tidb_intelligence_scores', ['target_id'], False),
    ])


def downgrade() -> None:
    """Downgrade schema."""
    for table in (
        'tidb_intelligence_scores',
        'tidb_intelligence_conflicts',
        'tidb_intelligence_negatives',
        'tidb_intelligence_decisions',
        'tidb_intelligence_actions',
        'tidb_intelligence_hypotheses',
        'tidb_intelligence_gaps',
        'tidb_intelligence_coverage',
        'tidb_intelligence_changes',
        'tidb_intelligence_history',
        'tidb_intelligence_evidence',
        'tidb_intelligence_observations',
        'tidb_intelligence_assets',
        'tidb_intelligence_targets',
    ):
        op.drop_table(table)
