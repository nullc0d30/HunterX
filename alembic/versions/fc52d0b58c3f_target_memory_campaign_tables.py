"""target memory & campaign intelligence tables

Revision ID: fc52d0b58c3f
Revises: b2e3f5a7c9d1
Create Date: 2026-08-10

Extends the TIDB schema with the Sprint 030 target memory & campaign
intelligence capability: memory observations with first/last seen tracking,
reproducible target snapshots, deterministic snapshot diffs, mission memory,
hypothesis memory (failed and successful), tool observation provenance, target
risk history, finding memory and recurrence detection, campaigns, coverage
gaps, revalidation state, attack-path history, preserved memory
contradictions and advisory next-action records.

Security boundary: every table stores canonical, normalized historical data
and references to evidence - never raw tool output, never credentials, never
exploit payloads. Memory is treated as untrusted data: confidence,
corroboration, freshness and contradiction state are stored alongside every
observation.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'fc52d0b58c3f'
down_revision: str | Sequence[str] | None = 'b2e3f5a7c9d1'
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


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'tidb_memory_observations',
        sa.Column('observation_key', sa.String(length=1024), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('observation_type', sa.String(length=32), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('normalized_value', sa.Text(), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('observation_count', sa.Integer(), nullable=False),
        sa.Column('first_mission', sa.String(length=26), nullable=False),
        sa.Column('last_mission', sa.String(length=26), nullable=False),
        sa.Column('first_source', sa.String(length=255), nullable=False),
        sa.Column('last_source', sa.String(length=255), nullable=False),
        sa.Column('current_state', sa.String(length=32), nullable=False),
        sa.Column('freshness', sa.String(length=16), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('source_reliability', sa.String(length=32), nullable=False),
        sa.Column('corroboration_count', sa.Integer(), nullable=False),
        sa.Column('contradiction_state', sa.String(length=16), nullable=False),
        sa.Column('validity', sa.String(length=16), nullable=False),
        sa.Column('expires_at', sa.String(length=32), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_memory_obs_target_type_state', 'tidb_memory_observations', ['target_id', 'observation_type', 'current_state'], unique=False)
    op.create_index('ix_tidb_memory_obs_target_lastseen', 'tidb_memory_observations', ['target_id', 'last_seen'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_asset_key'), 'tidb_memory_observations', ['asset_key'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_current_state'), 'tidb_memory_observations', ['current_state'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_first_seen'), 'tidb_memory_observations', ['first_seen'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_freshness'), 'tidb_memory_observations', ['freshness'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_last_seen'), 'tidb_memory_observations', ['last_seen'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_mission_id'), 'tidb_memory_observations', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_observation_key'), 'tidb_memory_observations', ['observation_key'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_observation_type'), 'tidb_memory_observations', ['observation_type'], unique=False)
    op.create_index(op.f('ix_tidb_memory_observations_target_id'), 'tidb_memory_observations', ['target_id'], unique=False)
    op.create_table(
        'tidb_target_snapshots',
        sa.Column('snapshot_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('observation_count', sa.Integer(), nullable=False),
        sa.Column('state_hash', sa.String(length=64), nullable=False),
        sa.Column('state', sa.JSON(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_snapshots_target_created', 'tidb_target_snapshots', ['target_id', 'created_at'], unique=False)
    op.create_index(op.f('ix_tidb_target_snapshots_mission_id'), 'tidb_target_snapshots', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_snapshots_snapshot_id'), 'tidb_target_snapshots', ['snapshot_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_snapshots_state_hash'), 'tidb_target_snapshots', ['state_hash'], unique=False)
    op.create_index(op.f('ix_tidb_target_snapshots_target_id'), 'tidb_target_snapshots', ['target_id'], unique=False)
    op.create_table(
        'tidb_target_diffs',
        sa.Column('diff_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('snapshot_a_id', sa.String(length=26), nullable=False),
        sa.Column('snapshot_b_id', sa.String(length=26), nullable=False),
        sa.Column('state_hash_a', sa.String(length=64), nullable=False),
        sa.Column('state_hash_b', sa.String(length=64), nullable=False),
        sa.Column('changes', sa.JSON(), nullable=False),
        sa.Column('deterministic', sa.Boolean(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_diffs_target_snapshots', 'tidb_target_diffs', ['target_id', 'snapshot_a_id', 'snapshot_b_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_diffs_diff_id'), 'tidb_target_diffs', ['diff_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_diffs_target_id'), 'tidb_target_diffs', ['target_id'], unique=False)
    op.create_table(
        'tidb_mission_memories',
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('scope', sa.String(length=512), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=False),
        sa.Column('ended_at', sa.String(length=32), nullable=False),
        sa.Column('tools_used', sa.JSON(), nullable=False),
        sa.Column('assets_discovered', sa.JSON(), nullable=False),
        sa.Column('findings_discovered', sa.JSON(), nullable=False),
        sa.Column('findings_validated', sa.JSON(), nullable=False),
        sa.Column('pocs_generated', sa.JSON(), nullable=False),
        sa.Column('hypotheses', sa.JSON(), nullable=False),
        sa.Column('successful_hypotheses', sa.JSON(), nullable=False),
        sa.Column('failed_hypotheses', sa.JSON(), nullable=False),
        sa.Column('blocked_tests', sa.JSON(), nullable=False),
        sa.Column('tool_failures', sa.JSON(), nullable=False),
        sa.Column('coverage_achieved', sa.JSON(), nullable=False),
        sa.Column('coverage_gaps', sa.JSON(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_mission_memories_target', 'tidb_mission_memories', ['target_id', 'mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_memories_mission_id'), 'tidb_mission_memories', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_memories_target_id'), 'tidb_mission_memories', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_memories_tenant'), 'tidb_mission_memories', ['tenant'], unique=False)
    op.create_table(
        'tidb_hypothesis_memories',
        sa.Column('memory_id', sa.String(length=26), nullable=False),
        sa.Column('hypothesis_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('statement', sa.Text(), nullable=False),
        sa.Column('hypothesis_type', sa.String(length=48), nullable=False),
        sa.Column('outcome', sa.String(length=16), nullable=False),
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('evidence_observed', sa.Text(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('tested_at', sa.String(length=32), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('vulnerability_type', sa.String(length=48), nullable=False),
        sa.Column('asset_type', sa.String(length=48), nullable=False),
        sa.Column('technology', sa.String(length=128), nullable=False),
        sa.Column('endpoint_pattern', sa.String(length=512), nullable=False),
        sa.Column('parameter_pattern', sa.String(length=512), nullable=False),
        sa.Column('authentication_context', sa.String(length=255), nullable=False),
        sa.Column('validation_strategy', sa.String(length=128), nullable=False),
        sa.Column('poc_strategy', sa.String(length=128), nullable=False),
        sa.Column('evidence_pattern', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_hyp_memories_target_outcome', 'tidb_hypothesis_memories', ['target_id', 'outcome'], unique=False)
    op.create_index(op.f('ix_tidb_hypothesis_memories_hypothesis_id'), 'tidb_hypothesis_memories', ['hypothesis_id'], unique=False)
    op.create_index(op.f('ix_tidb_hypothesis_memories_memory_id'), 'tidb_hypothesis_memories', ['memory_id'], unique=False)
    op.create_index(op.f('ix_tidb_hypothesis_memories_mission_id'), 'tidb_hypothesis_memories', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_hypothesis_memories_outcome'), 'tidb_hypothesis_memories', ['outcome'], unique=False)
    op.create_index(op.f('ix_tidb_hypothesis_memories_target_id'), 'tidb_hypothesis_memories', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_hypothesis_memories_tenant'), 'tidb_hypothesis_memories', ['tenant'], unique=False)
    op.create_table(
        'tidb_tool_observations',
        sa.Column('tool', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('execution_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('scope', sa.String(length=512), nullable=False),
        sa.Column('timestamp', sa.String(length=32), nullable=False),
        sa.Column('normalized_result', sa.JSON(), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('derived_entities', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_tool_obs_target_tool', 'tidb_tool_observations', ['target_id', 'tool'], unique=False)
    op.create_index(op.f('ix_tidb_tool_observations_execution_id'), 'tidb_tool_observations', ['execution_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_observations_target_id'), 'tidb_tool_observations', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_observations_tenant'), 'tidb_tool_observations', ['tenant'], unique=False)
    op.create_index(op.f('ix_tidb_tool_observations_timestamp'), 'tidb_tool_observations', ['timestamp'], unique=False)
    op.create_index(op.f('ix_tidb_tool_observations_tool'), 'tidb_tool_observations', ['tool'], unique=False)
    op.create_table(
        'tidb_target_risks',
        sa.Column('risk_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('campaign_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('risk_level', sa.String(length=16), nullable=False),
        sa.Column('previous_risk_level', sa.String(length=16), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('detected_at', sa.String(length=32), nullable=False),
        sa.Column('driving_changes', sa.JSON(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_target_risks_target_detected', 'tidb_target_risks', ['target_id', 'detected_at'], unique=False)
    op.create_index(op.f('ix_tidb_target_risks_campaign_id'), 'tidb_target_risks', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_risks_mission_id'), 'tidb_target_risks', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_risks_risk_id'), 'tidb_target_risks', ['risk_id'], unique=False)
    op.create_index(op.f('ix_tidb_target_risks_risk_level'), 'tidb_target_risks', ['risk_level'], unique=False)
    op.create_index(op.f('ix_tidb_target_risks_target_id'), 'tidb_target_risks', ['target_id'], unique=False)
    op.create_table(
        'tidb_finding_memories',
        sa.Column('finding_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('vulnerability_class', sa.String(length=64), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('first_detected', sa.String(length=32), nullable=False),
        sa.Column('first_validated', sa.String(length=32), nullable=False),
        sa.Column('last_validated', sa.String(length=32), nullable=False),
        sa.Column('last_observed', sa.String(length=32), nullable=False),
        sa.Column('remediation_state', sa.String(length=32), nullable=False),
        sa.Column('retest_state', sa.String(length=32), nullable=False),
        sa.Column('reopened_count', sa.Integer(), nullable=False),
        sa.Column('closed_at', sa.String(length=32), nullable=False),
        sa.Column('affected_assets', sa.JSON(), nullable=False),
        sa.Column('affected_endpoints', sa.JSON(), nullable=False),
        sa.Column('root_cause', sa.Text(), nullable=False),
        sa.Column('recurrence_count', sa.Integer(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_finding_memories_target_status', 'tidb_finding_memories', ['target_id', 'remediation_state'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_finding_id'), 'tidb_finding_memories', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_mission_id'), 'tidb_finding_memories', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_remediation_state'), 'tidb_finding_memories', ['remediation_state'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_severity'), 'tidb_finding_memories', ['severity'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_status'), 'tidb_finding_memories', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_target_id'), 'tidb_finding_memories', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_memories_tenant'), 'tidb_finding_memories', ['tenant'], unique=False)
    op.create_table(
        'tidb_finding_recurrences',
        sa.Column('recurrence_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('campaign_id', sa.String(length=26), nullable=False),
        sa.Column('original_finding_id', sa.String(length=26), nullable=False),
        sa.Column('new_finding_id', sa.String(length=26), nullable=False),
        sa.Column('vulnerability_class', sa.String(length=64), nullable=False),
        sa.Column('root_cause', sa.Text(), nullable=False),
        sa.Column('previous_location', sa.Text(), nullable=False),
        sa.Column('new_location', sa.Text(), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('detected_at', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_finding_recurrences_campaign_id'), 'tidb_finding_recurrences', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_recurrences_kind'), 'tidb_finding_recurrences', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_finding_recurrences_recurrence_id'), 'tidb_finding_recurrences', ['recurrence_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_recurrences_target_id'), 'tidb_finding_recurrences', ['target_id'], unique=False)
    op.create_table(
        'tidb_campaigns',
        sa.Column('campaign_id', sa.String(length=26), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('objective', sa.Text(), nullable=False),
        sa.Column('scope', sa.String(length=512), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('target_ids', sa.JSON(), nullable=False),
        sa.Column('mission_ids', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=False),
        sa.Column('ended_at', sa.String(length=32), nullable=True),
        sa.Column('risk_history', sa.JSON(), nullable=False),
        sa.Column('findings', sa.JSON(), nullable=False),
        sa.Column('coverage', sa.JSON(), nullable=False),
        sa.Column('changes', sa.JSON(), nullable=False),
        sa.Column('attack_paths', sa.JSON(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_campaigns_tenant_status', 'tidb_campaigns', ['tenant', 'status'], unique=False)
    op.create_index(op.f('ix_tidb_campaigns_campaign_id'), 'tidb_campaigns', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_tidb_campaigns_status'), 'tidb_campaigns', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_campaigns_tenant'), 'tidb_campaigns', ['tenant'], unique=False)
    op.create_table(
        'tidb_coverage_gaps',
        sa.Column('gap_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('campaign_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('significance', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('detected_at', sa.String(length=32), nullable=False),
        sa.Column('resolved_at', sa.String(length=32), nullable=True),
        sa.Column('candidate_tools', sa.JSON(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_gaps_target_status', 'tidb_coverage_gaps', ['target_id', 'status'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_asset_key'), 'tidb_coverage_gaps', ['asset_key'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_campaign_id'), 'tidb_coverage_gaps', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_gap_id'), 'tidb_coverage_gaps', ['gap_id'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_kind'), 'tidb_coverage_gaps', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_significance'), 'tidb_coverage_gaps', ['significance'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_status'), 'tidb_coverage_gaps', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_coverage_gaps_target_id'), 'tidb_coverage_gaps', ['target_id'], unique=False)
    op.create_table(
        'tidb_revalidations',
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('observation_key', sa.String(length=1024), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('observation_type', sa.String(length=32), nullable=False),
        sa.Column('freshness', sa.String(length=16), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('priority', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_revalidations_target_status', 'tidb_revalidations', ['target_id', 'status'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_asset_key'), 'tidb_revalidations', ['asset_key'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_freshness'), 'tidb_revalidations', ['freshness'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_observation_key'), 'tidb_revalidations', ['observation_key'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_plan_id'), 'tidb_revalidations', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_priority'), 'tidb_revalidations', ['priority'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_status'), 'tidb_revalidations', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_target_id'), 'tidb_revalidations', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_revalidations_last_seen'), 'tidb_revalidations', ['last_seen'], unique=False)
    op.create_table(
        'tidb_attack_path_memories',
        sa.Column('path_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('campaign_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('nodes', sa.JSON(), nullable=False),
        sa.Column('edges', sa.JSON(), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('changes', sa.JSON(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tidb_path_memories_target_status', 'tidb_attack_path_memories', ['target_id', 'status'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_campaign_id'), 'tidb_attack_path_memories', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_mission_id'), 'tidb_attack_path_memories', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_path_id'), 'tidb_attack_path_memories', ['path_id'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_status'), 'tidb_attack_path_memories', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_target_id'), 'tidb_attack_path_memories', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_tenant'), 'tidb_attack_path_memories', ['tenant'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_first_seen'), 'tidb_attack_path_memories', ['first_seen'], unique=False)
    op.create_index(op.f('ix_tidb_attack_path_memories_last_seen'), 'tidb_attack_path_memories', ['last_seen'], unique=False)
    op.create_table(
        'tidb_memory_contradictions',
        sa.Column('contradiction_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.String(length=1024), nullable=False),
        sa.Column('observation_key', sa.String(length=1024), nullable=False),
        sa.Column('observations', sa.JSON(), nullable=False),
        sa.Column('tools', sa.JSON(), nullable=False),
        sa.Column('state', sa.String(length=16), nullable=False),
        sa.Column('resolution', sa.Text(), nullable=False),
        sa.Column('detected_at', sa.String(length=32), nullable=False),
        sa.Column('resolved_at', sa.String(length=32), nullable=True),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_memory_contradictions_asset_key'), 'tidb_memory_contradictions', ['asset_key'], unique=False)
    op.create_index(op.f('ix_tidb_memory_contradictions_contradiction_id'), 'tidb_memory_contradictions', ['contradiction_id'], unique=False)
    op.create_index(op.f('ix_tidb_memory_contradictions_observation_key'), 'tidb_memory_contradictions', ['observation_key'], unique=False)
    op.create_index(op.f('ix_tidb_memory_contradictions_state'), 'tidb_memory_contradictions', ['state'], unique=False)
    op.create_index(op.f('ix_tidb_memory_contradictions_target_id'), 'tidb_memory_contradictions', ['target_id'], unique=False)
    op.create_table(
        'tidb_next_actions',
        sa.Column('recommendation_id', sa.String(length=26), nullable=False),
        sa.Column('target_id', sa.String(length=26), nullable=False),
        sa.Column('campaign_id', sa.String(length=26), nullable=False),
        sa.Column('action', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('priority', sa.String(length=16), nullable=False),
        sa.Column('required_tool_capabilities', sa.JSON(), nullable=False),
        sa.Column('evidence_required', sa.JSON(), nullable=False),
        sa.Column('expected_outcome', sa.Text(), nullable=False),
        sa.Column('historical_context', sa.JSON(), nullable=False),
        *_envelope(),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_next_actions_action'), 'tidb_next_actions', ['action'], unique=False)
    op.create_index(op.f('ix_tidb_next_actions_campaign_id'), 'tidb_next_actions', ['campaign_id'], unique=False)
    op.create_index(op.f('ix_tidb_next_actions_priority'), 'tidb_next_actions', ['priority'], unique=False)
    op.create_index(op.f('ix_tidb_next_actions_recommendation_id'), 'tidb_next_actions', ['recommendation_id'], unique=False)
    op.create_index(op.f('ix_tidb_next_actions_target_id'), 'tidb_next_actions', ['target_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('tidb_next_actions')
    op.drop_table('tidb_memory_contradictions')
    op.drop_table('tidb_attack_path_memories')
    op.drop_table('tidb_revalidations')
    op.drop_table('tidb_coverage_gaps')
    op.drop_table('tidb_campaigns')
    op.drop_table('tidb_finding_recurrences')
    op.drop_table('tidb_finding_memories')
    op.drop_table('tidb_target_risks')
    op.drop_table('tidb_tool_observations')
    op.drop_table('tidb_hypothesis_memories')
    op.drop_table('tidb_mission_memories')
    op.drop_table('tidb_target_diffs')
    op.drop_table('tidb_target_snapshots')
    op.drop_table('tidb_memory_observations')
