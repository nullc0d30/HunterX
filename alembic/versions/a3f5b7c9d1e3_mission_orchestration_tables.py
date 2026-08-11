"""autonomous mission orchestration tables

Sprint 032. Creates the normalized Autonomous Mission Orchestration entities:
orchestrated missions, runs, phases, actions, decisions, hypotheses, branches,
checkpoints, policies, objectives, coverage cells, timeline entries,
observations, negative evidence, baselines, reasoning-trace entries, telemetry
snapshots and impact analyses.

Revision ID: a3f5b7c9d1e3
Revises: fc52d0b58c3f
Create Date: 2026-08-10 14:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a3f5b7c9d1e3'
down_revision: str | Sequence[str] | None = 'fc52d0b58c3f'
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
    _create('tidb_mission_orchestrations', [
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('objective', sa.String(length=64), nullable=False),
        sa.Column('mode', sa.String(length=32), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('strategy', sa.String(length=32), nullable=False),
        sa.Column('current_phase', sa.String(length=64), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('tenant', sa.String(length=64), nullable=False),
        sa.Column('authorization_context', sa.String(length=64), nullable=False),
        sa.Column('policy', sa.JSON(), nullable=False),
        sa.Column('budget', sa.JSON(), nullable=False),
        sa.Column('coverage_ratio', sa.Float(), nullable=False),
        sa.Column('outcome', sa.JSON(), nullable=True),
    ], [
('ix_tidb_mission_orchestrations_mission_id', 'tidb_mission_orchestrations', ['mission_id'], False),
('ix_tidb_mission_orchestrations_state', 'tidb_mission_orchestrations', ['state'], False),
('ix_tidb_mission_orchestrations_objective', 'tidb_mission_orchestrations', ['objective'], False),
('ix_tidb_mission_orchestrations_tenant', 'tidb_mission_orchestrations', ['tenant'], False),
    ])

    _create('tidb_mission_runs', [
        sa.Column('run_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=False),
        sa.Column('finished_at', sa.String(length=32), nullable=True),
        sa.Column('resumed_from_run_id', sa.String(length=26), nullable=False),
        sa.Column('checkpoint_id', sa.String(length=26), nullable=False),
        sa.Column('last_action_id', sa.String(length=26), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_mission_runs_run_id', 'tidb_mission_runs', ['run_id'], False),
        ('ix_tidb_mission_runs_mission_id', 'tidb_mission_runs', ['mission_id'], False),
        ('ix_tidb_mission_runs_status', 'tidb_mission_runs', ['status'], False),
    ])

    _create('tidb_mission_phases', [
        sa.Column('phase_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('phase', sa.String(length=64), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=False),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        sa.Column('detail', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_mission_phases_phase_id', 'tidb_mission_phases', ['phase_id'], False),
        ('ix_tidb_mission_phases_mission_id', 'tidb_mission_phases', ['mission_id'], False),
        ('ix_tidb_mission_phases_phase', 'tidb_mission_phases', ['phase'], False),
    ])

    _create('tidb_mission_actions', [
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('asset_key', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=True),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        sa.Column('result', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_mission_actions_action_id', 'tidb_mission_actions', ['action_id'], False),
        ('ix_tidb_mission_actions_mission_id', 'tidb_mission_actions', ['mission_id'], False),
        ('ix_tidb_mission_actions_capability', 'tidb_mission_actions', ['capability'], False),
        ('ix_tidb_mission_actions_tool_id', 'tidb_mission_actions', ['tool_id'], False),
        ('ix_tidb_mission_actions_mission_status', 'tidb_mission_actions', ['mission_id', 'status'], False),
    ])

    _create('tidb_mission_decisions', [
        sa.Column('decision_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('next_action', sa.String(length=26), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('expected_result', sa.Text(), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
        sa.Column('dependencies', sa.JSON(), nullable=False),
        sa.Column('alternatives', sa.JSON(), nullable=False),
        sa.Column('information_gain', sa.Float(), nullable=False),
        sa.Column('factors', sa.JSON(), nullable=False),
        sa.Column('ai_assisted', sa.Boolean(), nullable=False),
        sa.Column('latency_ms', sa.Integer(), nullable=False),
    ], [
        ('ix_tidb_mission_decisions_decision_id', 'tidb_mission_decisions', ['decision_id'], False),
        ('ix_tidb_mission_decisions_mission_id', 'tidb_mission_decisions', ['mission_id'], False),
        ('ix_tidb_mission_decisions_next_action', 'tidb_mission_decisions', ['next_action'], False),
    ])

    _create('tidb_mission_hypotheses', [
        sa.Column('hypothesis_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('statement', sa.Text(), nullable=False),
        sa.Column('category', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('behavior_class', sa.String(length=32), nullable=False),
        sa.Column('supporting_evidence', sa.JSON(), nullable=False),
        sa.Column('contradicting_evidence', sa.JSON(), nullable=False),
        sa.Column('tested_actions', sa.JSON(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
        sa.Column('validation_strategy', sa.Text(), nullable=False),
        sa.Column('proof_strategy', sa.Text(), nullable=False),
        sa.Column('proposed_by', sa.String(length=64), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
    ], [
('ix_tidb_mission_hypotheses_hypothesis_id', 'tidb_mission_hypotheses', ['hypothesis_id'], False),
('ix_tidb_mission_hypotheses_mission_id', 'tidb_mission_hypotheses', ['mission_id'], False),
('ix_tidb_mission_hypotheses_state', 'tidb_mission_hypotheses', ['state'], False),
('ix_tidb_mission_hypotheses_priority', 'tidb_mission_hypotheses', ['priority'], False),
    ])

    _create('tidb_mission_branches', [
        sa.Column('branch_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('parent_branch_id', sa.String(length=26), nullable=False),
        sa.Column('hypothesis_id', sa.String(length=26), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('actions', sa.JSON(), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('cost', sa.Float(), nullable=False),
        sa.Column('priority', sa.Float(), nullable=False),
        sa.Column('outcome', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_mission_branches_branch_id', 'tidb_mission_branches', ['branch_id'], False),
        ('ix_tidb_mission_branches_mission_id', 'tidb_mission_branches', ['mission_id'], False),
        ('ix_tidb_mission_branches_state', 'tidb_mission_branches', ['state'], False),
    ])

    _create('tidb_mission_checkpoints', [
        sa.Column('checkpoint_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('label', sa.Text(), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('created_at_iso', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_mission_checkpoints_checkpoint_id', 'tidb_mission_checkpoints', ['checkpoint_id'], False),
        ('ix_tidb_mission_checkpoints_mission_id', 'tidb_mission_checkpoints', ['mission_id'], False),
    ])

    _create('tidb_mission_policies', [
        sa.Column('policy_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('objective_name', sa.String(length=64), nullable=False),
        sa.Column('strategy', sa.String(length=32), nullable=False),
        sa.Column('allowed_techniques', sa.JSON(), nullable=False),
        sa.Column('resource_budget', sa.Integer(), nullable=False),
        sa.Column('time_budget_seconds', sa.Integer(), nullable=False),
        sa.Column('validation_depth', sa.String(length=32), nullable=False),
        sa.Column('proof_depth', sa.String(length=32), nullable=False),
        sa.Column('coverage_target', sa.Float(), nullable=False),
        sa.Column('stop_conditions', sa.JSON(), nullable=False),
        sa.Column('max_concurrency', sa.Integer(), nullable=False),
        sa.Column('rate_limit_per_minute', sa.Integer(), nullable=False),
    ], [
        ('ix_tidb_mission_policies_policy_id', 'tidb_mission_policies', ['policy_id'], False),
        ('ix_tidb_mission_policies_mission_id', 'tidb_mission_policies', ['mission_id'], False),
    ])

    _create('tidb_mission_objectives', [
        sa.Column('record_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('objective', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
    ], [
        ('ix_tidb_mission_objectives_record_id', 'tidb_mission_objectives', ['record_id'], False),
        ('ix_tidb_mission_objectives_mission_id', 'tidb_mission_objectives', ['mission_id'], False),
    ])

    _create('tidb_mission_coverage', [
        sa.Column('cell_key', sa.String(length=128), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.Text(), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('tested_at', sa.String(length=32), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_mission_coverage_cell_key', 'tidb_mission_coverage', ['cell_key'], False),
        ('ix_tidb_mission_coverage_mission_id', 'tidb_mission_coverage', ['mission_id'], False),
        ('ix_tidb_mission_coverage_capability', 'tidb_mission_coverage', ['capability'], False),
        ('ix_tidb_mission_coverage_mission_cap', 'tidb_mission_coverage', ['mission_id', 'capability'], False),
    ])

    _create('tidb_mission_timelines', [
        sa.Column('entry_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('event_type', sa.String(length=128), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('occurred_at', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_mission_timelines_entry_id', 'tidb_mission_timelines', ['entry_id'], False),
        ('ix_tidb_mission_timelines_mission_id', 'tidb_mission_timelines', ['mission_id'], False),
        ('ix_tidb_mission_timelines_event_type', 'tidb_mission_timelines', ['event_type'], False),
    ])

    _create('tidb_mission_observations', [
        sa.Column('observation_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('action_id', sa.String(length=26), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('asset_key', sa.Text(), nullable=False),
        sa.Column('observation_type', sa.String(length=64), nullable=False),
        sa.Column('content', sa.JSON(), nullable=False),
        sa.Column('evidence_ref', sa.String(length=128), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
    ], [
('ix_tidb_mission_observations_observation_id', 'tidb_mission_observations', ['observation_id'], False),
('ix_tidb_mission_observations_mission_id', 'tidb_mission_observations', ['mission_id'], False),
('ix_tidb_mission_observations_asset_key', 'tidb_mission_observations', ['asset_key'], False),
    ])

    _create('tidb_mission_negative', [
        sa.Column('record_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.Text(), nullable=False),
        sa.Column('capability', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('tool_id', sa.String(length=128), nullable=False),
        sa.Column('tool_version', sa.String(length=64), nullable=False),
        sa.Column('input_hash', sa.String(length=64), nullable=False),
        sa.Column('outcome', sa.Text(), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
    ], [
        ('ix_tidb_mission_negative_record_id', 'tidb_mission_negative', ['record_id'], False),
        ('ix_tidb_mission_negative_mission_id', 'tidb_mission_negative', ['mission_id'], False),
        ('ix_tidb_mission_negative_asset_key', 'tidb_mission_negative', ['asset_key'], False),
        ('ix_tidb_mission_negative_capability', 'tidb_mission_negative', ['capability'], False),
    ])

    _create('tidb_mission_baselines', [
        sa.Column('baseline_id', sa.String(length=64), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('asset_key', sa.Text(), nullable=False),
        sa.Column('request_fingerprint', sa.Text(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('headers', sa.JSON(), nullable=False),
        sa.Column('content_length', sa.Integer(), nullable=False),
        sa.Column('body_hash', sa.String(length=64), nullable=False),
        sa.Column('timing_ms', sa.Integer(), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
    ], [
        ('ix_tidb_mission_baselines_baseline_id', 'tidb_mission_baselines', ['baseline_id'], False),
        ('ix_tidb_mission_baselines_mission_id', 'tidb_mission_baselines', ['mission_id'], False),
        ('ix_tidb_mission_baselines_asset_key', 'tidb_mission_baselines', ['asset_key'], False),
    ])

    _create('tidb_mission_reasoning', [
        sa.Column('entry_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('node_id', sa.String(length=64), nullable=False),
        sa.Column('content', sa.JSON(), nullable=False),
        sa.Column('parent_entry_id', sa.String(length=26), nullable=False),
        sa.Column('occurred_at', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_mission_reasoning_entry_id', 'tidb_mission_reasoning', ['entry_id'], False),
        ('ix_tidb_mission_reasoning_mission_id', 'tidb_mission_reasoning', ['mission_id'], False),
        ('ix_tidb_mission_reasoning_kind', 'tidb_mission_reasoning', ['kind'], False),
    ])

    _create('tidb_mission_telemetry', [
        sa.Column('snapshot_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('recorded_at', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_mission_telemetry_snapshot_id', 'tidb_mission_telemetry', ['snapshot_id'], False),
        ('ix_tidb_mission_telemetry_mission_id', 'tidb_mission_telemetry', ['mission_id'], False),
    ])

    _create('tidb_mission_impact', [
        sa.Column('impact_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('finding_id', sa.String(length=26), nullable=False),
        sa.Column('impact', sa.JSON(), nullable=False),
        sa.Column('analyzed_at', sa.String(length=32), nullable=False),
    ], [
        ('ix_tidb_mission_impact_impact_id', 'tidb_mission_impact', ['impact_id'], False),
        ('ix_tidb_mission_impact_mission_id', 'tidb_mission_impact', ['mission_id'], False),
        ('ix_tidb_mission_impact_finding_id', 'tidb_mission_impact', ['finding_id'], False),
    ])


def downgrade() -> None:
    """Downgrade schema."""
    for name in [
        'tidb_mission_impact',
        'tidb_mission_telemetry',
        'tidb_mission_reasoning',
        'tidb_mission_baselines',
        'tidb_mission_negative',
        'tidb_mission_observations',
        'tidb_mission_timelines',
        'tidb_mission_coverage',
        'tidb_mission_objectives',
        'tidb_mission_policies',
        'tidb_mission_checkpoints',
        'tidb_mission_branches',
        'tidb_mission_hypotheses',
        'tidb_mission_decisions',
        'tidb_mission_actions',
        'tidb_mission_phases',
        'tidb_mission_runs',
        'tidb_mission_orchestrations',
    ]:
        op.drop_table(name)
