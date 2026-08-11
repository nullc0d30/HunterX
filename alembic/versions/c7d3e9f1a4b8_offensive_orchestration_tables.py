"""offensive orchestration tables

Revision ID: c7d3e9f1a4b8
Revises: a1b2c3d4e5f6
Create Date: 2026-08-10

Extends the TIDB schema with the Wave 14 offensive tool orchestration
canonical inventory: execution plans, phases and steps, tool selections,
execution dependencies, execution checkpoints, gate policy decisions, replan
events, coverage metrics, mission quality scores, classified mission failures
and per-step task history.

Security boundary: every table stores orchestration metadata, canonical
targets, tool selections and redacted evidence references only - never exploit
payloads, never credentials and never out-of-scope request material.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c7d3e9f1a4b8'
down_revision: str | Sequence[str] | None = 'a1b2c3d4e5f6'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'tidb_mission_plan_records',
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_version', sa.Integer(), nullable=False),
        sa.Column('objective', sa.Text(), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('scope', sa.JSON(), nullable=False),
        sa.Column('policies', sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_plan_records_plan_id'), 'tidb_mission_plan_records', ['plan_id'], unique=True)
    op.create_index(op.f('ix_tidb_mission_plan_records_mission_id'), 'tidb_mission_plan_records', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_plan_records_state'), 'tidb_mission_plan_records', ['state'], unique=False)
    op.create_index('ix_tidb_mission_plan_records_mission_version', 'tidb_mission_plan_records', ['mission_id', 'plan_version'], unique=False)

    op.create_table(
        'tidb_mission_phase_records',
        sa.Column('phase_id', sa.String(length=64), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('order', sa.Integer(), nullable=False),
        sa.Column('parallel', sa.Boolean(), nullable=False),
        sa.Column('optional', sa.Boolean(), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('depends_on', sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_phase_records_phase_id'), 'tidb_mission_phase_records', ['phase_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_phase_records_plan_id'), 'tidb_mission_phase_records', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_phase_records_kind'), 'tidb_mission_phase_records', ['kind'], unique=False)
    op.create_index('ix_tidb_mission_phase_records_plan_kind', 'tidb_mission_phase_records', ['plan_id', 'kind'], unique=False)

    op.create_table(
        'tidb_mission_step_records',
        sa.Column('step_id', sa.String(length=64), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('phase_id', sa.String(length=64), nullable=False),
        sa.Column('action', sa.String(length=255), nullable=False),
        sa.Column('capability', sa.String(length=255), nullable=False),
        sa.Column('tool_id', sa.String(length=255), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('target_type', sa.String(length=64), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('depends_on', sa.JSON(), nullable=False),
        sa.Column('condition', sa.Text(), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('timeout_seconds', sa.Float(), nullable=False),
        sa.Column('retryable', sa.Boolean(), nullable=False),
        sa.Column('safety_class', sa.String(length=32), nullable=False),
        sa.Column('evidence_requirements', sa.JSON(), nullable=False),
        sa.Column('success_criteria', sa.JSON(), nullable=False),
        sa.Column('fallback_tools', sa.JSON(), nullable=False),
        sa.Column('execution_id', sa.String(length=26), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=True),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_step_records_step_id'), 'tidb_mission_step_records', ['step_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_step_records_plan_id'), 'tidb_mission_step_records', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_step_records_phase_id'), 'tidb_mission_step_records', ['phase_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_step_records_capability'), 'tidb_mission_step_records', ['capability'], unique=False)
    op.create_index(op.f('ix_tidb_mission_step_records_tool_id'), 'tidb_mission_step_records', ['tool_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_step_records_state'), 'tidb_mission_step_records', ['state'], unique=False)

    op.create_table(
        'tidb_execution_dependencies',
        sa.Column('dependency_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('source_step_id', sa.String(length=64), nullable=False),
        sa.Column('target_step_id', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_execution_dependencies_dependency_id'), 'tidb_execution_dependencies', ['dependency_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_dependencies_plan_id'), 'tidb_execution_dependencies', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_dependencies_source_step_id'), 'tidb_execution_dependencies', ['source_step_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_dependencies_target_step_id'), 'tidb_execution_dependencies', ['target_step_id'], unique=False)
    op.create_index('ix_tidb_execution_dependencies_plan_target', 'tidb_execution_dependencies', ['plan_id', 'target_step_id'], unique=False)

    op.create_table(
        'tidb_execution_checkpoints',
        sa.Column('checkpoint_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('checkpoint_version', sa.Integer(), nullable=False),
        sa.Column('plan_version', sa.Integer(), nullable=False),
        sa.Column('label', sa.String(length=255), nullable=False),
        sa.Column('state', sa.JSON(), nullable=False),
        sa.Column('completed_steps', sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_execution_checkpoints_checkpoint_id'), 'tidb_execution_checkpoints', ['checkpoint_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_checkpoints_plan_id'), 'tidb_execution_checkpoints', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_checkpoints_mission_id'), 'tidb_execution_checkpoints', ['mission_id'], unique=False)

    op.create_table(
        'tidb_execution_policy_decisions',
        sa.Column('decision_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('step_id', sa.String(length=64), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('allowed', sa.Boolean(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('detail', sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_execution_policy_decisions_decision_id'), 'tidb_execution_policy_decisions', ['decision_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_policy_decisions_mission_id'), 'tidb_execution_policy_decisions', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_policy_decisions_plan_id'), 'tidb_execution_policy_decisions', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_policy_decisions_step_id'), 'tidb_execution_policy_decisions', ['step_id'], unique=False)
    op.create_index(op.f('ix_tidb_execution_policy_decisions_kind'), 'tidb_execution_policy_decisions', ['kind'], unique=False)

    op.create_table(
        'tidb_tool_selection_records',
        sa.Column('selection_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('step_id', sa.String(length=64), nullable=False),
        sa.Column('capability', sa.String(length=255), nullable=False),
        sa.Column('tool_id', sa.String(length=255), nullable=False),
        sa.Column('alternative_tools', sa.JSON(), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('reasons', sa.JSON(), nullable=False),
        sa.Column('fallback_of', sa.String(length=255), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_tool_selection_records_selection_id'), 'tidb_tool_selection_records', ['selection_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_selection_records_mission_id'), 'tidb_tool_selection_records', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_selection_records_plan_id'), 'tidb_tool_selection_records', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_selection_records_step_id'), 'tidb_tool_selection_records', ['step_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_selection_records_capability'), 'tidb_tool_selection_records', ['capability'], unique=False)
    op.create_index(op.f('ix_tidb_tool_selection_records_tool_id'), 'tidb_tool_selection_records', ['tool_id'], unique=False)

    op.create_table(
        'tidb_tool_fallbacks',
        sa.Column('fallback_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('step_id', sa.String(length=64), nullable=False),
        sa.Column('primary_tool', sa.String(length=255), nullable=False),
        sa.Column('fallback_tool', sa.String(length=255), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_tool_fallbacks_fallback_id'), 'tidb_tool_fallbacks', ['fallback_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_fallbacks_mission_id'), 'tidb_tool_fallbacks', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_fallbacks_plan_id'), 'tidb_tool_fallbacks', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_tool_fallbacks_step_id'), 'tidb_tool_fallbacks', ['step_id'], unique=False)

    op.create_table(
        'tidb_mission_replans',
        sa.Column('replan_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('previous_version', sa.Integer(), nullable=False),
        sa.Column('new_version', sa.Integer(), nullable=False),
        sa.Column('added_steps', sa.JSON(), nullable=False),
        sa.Column('removed_steps', sa.JSON(), nullable=False),
        sa.Column('blocked_assets', sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_replans_replan_id'), 'tidb_mission_replans', ['replan_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_replans_mission_id'), 'tidb_mission_replans', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_replans_plan_id'), 'tidb_mission_replans', ['plan_id'], unique=False)

    op.create_table(
        'tidb_mission_coverages',
        sa.Column('coverage_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('observed', sa.Integer(), nullable=False),
        sa.Column('expected', sa.Integer(), nullable=False),
        sa.Column('covered', sa.Integer(), nullable=False),
        sa.Column('fraction', sa.Float(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_coverages_coverage_id'), 'tidb_mission_coverages', ['coverage_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_coverages_mission_id'), 'tidb_mission_coverages', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_coverages_plan_id'), 'tidb_mission_coverages', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_coverages_kind'), 'tidb_mission_coverages', ['kind'], unique=False)
    op.create_index('ix_tidb_mission_coverages_mission_kind', 'tidb_mission_coverages', ['mission_id', 'kind'], unique=False)

    op.create_table(
        'tidb_mission_qualities',
        sa.Column('quality_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('factors', sa.JSON(), nullable=False),
        sa.Column('explainability', sa.JSON(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_qualities_quality_id'), 'tidb_mission_qualities', ['quality_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_qualities_mission_id'), 'tidb_mission_qualities', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_qualities_plan_id'), 'tidb_mission_qualities', ['plan_id'], unique=False)

    op.create_table(
        'tidb_mission_failures',
        sa.Column('failure_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('step_id', sa.String(length=64), nullable=False),
        sa.Column('execution_id', sa.String(length=26), nullable=False),
        sa.Column('tool_id', sa.String(length=255), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('failure_class', sa.String(length=32), nullable=False),
        sa.Column('management', sa.String(length=32), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
        sa.Column('retries', sa.Integer(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_failures_failure_id'), 'tidb_mission_failures', ['failure_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_failures_mission_id'), 'tidb_mission_failures', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_failures_plan_id'), 'tidb_mission_failures', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_failures_step_id'), 'tidb_mission_failures', ['step_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_failures_tool_id'), 'tidb_mission_failures', ['tool_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_failures_failure_class'), 'tidb_mission_failures', ['failure_class'], unique=False)

    op.create_table(
        'tidb_mission_task_history',
        sa.Column('history_id', sa.String(length=26), nullable=False),
        sa.Column('mission_id', sa.String(length=26), nullable=False),
        sa.Column('plan_id', sa.String(length=26), nullable=False),
        sa.Column('step_id', sa.String(length=64), nullable=False),
        sa.Column('execution_id', sa.String(length=26), nullable=False),
        sa.Column('tool_id', sa.String(length=255), nullable=False),
        sa.Column('target', sa.Text(), nullable=False),
        sa.Column('state', sa.String(length=32), nullable=False),
        sa.Column('started_at', sa.String(length=32), nullable=True),
        sa.Column('completed_at', sa.String(length=32), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=False),
        sa.Column('error', sa.Text(), nullable=False),
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
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_tidb_mission_task_history_history_id'), 'tidb_mission_task_history', ['history_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_task_history_mission_id'), 'tidb_mission_task_history', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_task_history_plan_id'), 'tidb_mission_task_history', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_task_history_step_id'), 'tidb_mission_task_history', ['step_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_task_history_execution_id'), 'tidb_mission_task_history', ['execution_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_task_history_tool_id'), 'tidb_mission_task_history', ['tool_id'], unique=False)
    op.create_index(op.f('ix_tidb_mission_task_history_state'), 'tidb_mission_task_history', ['state'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_mission_task_history_state'), table_name='tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_task_history_tool_id'), table_name='tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_task_history_execution_id'), table_name='tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_task_history_step_id'), table_name='tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_task_history_plan_id'), table_name='tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_task_history_mission_id'), table_name='tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_task_history_history_id'), table_name='tidb_mission_task_history')
    op.drop_table('tidb_mission_task_history')
    op.drop_index(op.f('ix_tidb_mission_failures_failure_class'), table_name='tidb_mission_failures')
    op.drop_index(op.f('ix_tidb_mission_failures_tool_id'), table_name='tidb_mission_failures')
    op.drop_index(op.f('ix_tidb_mission_failures_step_id'), table_name='tidb_mission_failures')
    op.drop_index(op.f('ix_tidb_mission_failures_plan_id'), table_name='tidb_mission_failures')
    op.drop_index(op.f('ix_tidb_mission_failures_mission_id'), table_name='tidb_mission_failures')
    op.drop_index(op.f('ix_tidb_mission_failures_failure_id'), table_name='tidb_mission_failures')
    op.drop_table('tidb_mission_failures')
    op.drop_index(op.f('ix_tidb_mission_qualities_plan_id'), table_name='tidb_mission_qualities')
    op.drop_index(op.f('ix_tidb_mission_qualities_mission_id'), table_name='tidb_mission_qualities')
    op.drop_index(op.f('ix_tidb_mission_qualities_quality_id'), table_name='tidb_mission_qualities')
    op.drop_table('tidb_mission_qualities')
    op.drop_index('ix_tidb_mission_coverages_mission_kind', table_name='tidb_mission_coverages')
    op.drop_index(op.f('ix_tidb_mission_coverages_kind'), table_name='tidb_mission_coverages')
    op.drop_index(op.f('ix_tidb_mission_coverages_plan_id'), table_name='tidb_mission_coverages')
    op.drop_index(op.f('ix_tidb_mission_coverages_mission_id'), table_name='tidb_mission_coverages')
    op.drop_index(op.f('ix_tidb_mission_coverages_coverage_id'), table_name='tidb_mission_coverages')
    op.drop_table('tidb_mission_coverages')
    op.drop_index(op.f('ix_tidb_mission_replans_plan_id'), table_name='tidb_mission_replans')
    op.drop_index(op.f('ix_tidb_mission_replans_mission_id'), table_name='tidb_mission_replans')
    op.drop_index(op.f('ix_tidb_mission_replans_replan_id'), table_name='tidb_mission_replans')
    op.drop_table('tidb_mission_replans')
    op.drop_index(op.f('ix_tidb_tool_fallbacks_step_id'), table_name='tidb_tool_fallbacks')
    op.drop_index(op.f('ix_tidb_tool_fallbacks_plan_id'), table_name='tidb_tool_fallbacks')
    op.drop_index(op.f('ix_tidb_tool_fallbacks_mission_id'), table_name='tidb_tool_fallbacks')
    op.drop_index(op.f('ix_tidb_tool_fallbacks_fallback_id'), table_name='tidb_tool_fallbacks')
    op.drop_table('tidb_tool_fallbacks')
    op.drop_index(op.f('ix_tidb_tool_selection_records_tool_id'), table_name='tidb_tool_selection_records')
    op.drop_index(op.f('ix_tidb_tool_selection_records_capability'), table_name='tidb_tool_selection_records')
    op.drop_index(op.f('ix_tidb_tool_selection_records_step_id'), table_name='tidb_tool_selection_records')
    op.drop_index(op.f('ix_tidb_tool_selection_records_plan_id'), table_name='tidb_tool_selection_records')
    op.drop_index(op.f('ix_tidb_tool_selection_records_mission_id'), table_name='tidb_tool_selection_records')
    op.drop_index(op.f('ix_tidb_tool_selection_records_selection_id'), table_name='tidb_tool_selection_records')
    op.drop_table('tidb_tool_selection_records')
    op.drop_index(op.f('ix_tidb_execution_policy_decisions_kind'), table_name='tidb_execution_policy_decisions')
    op.drop_index(op.f('ix_tidb_execution_policy_decisions_step_id'), table_name='tidb_execution_policy_decisions')
    op.drop_index(op.f('ix_tidb_execution_policy_decisions_plan_id'), table_name='tidb_execution_policy_decisions')
    op.drop_index(op.f('ix_tidb_execution_policy_decisions_mission_id'), table_name='tidb_execution_policy_decisions')
    op.drop_index(op.f('ix_tidb_execution_policy_decisions_decision_id'), table_name='tidb_execution_policy_decisions')
    op.drop_table('tidb_execution_policy_decisions')
    op.drop_index(op.f('ix_tidb_execution_checkpoints_mission_id'), table_name='tidb_execution_checkpoints')
    op.drop_index(op.f('ix_tidb_execution_checkpoints_plan_id'), table_name='tidb_execution_checkpoints')
    op.drop_index(op.f('ix_tidb_execution_checkpoints_checkpoint_id'), table_name='tidb_execution_checkpoints')
    op.drop_table('tidb_execution_checkpoints')
    op.drop_index('ix_tidb_execution_dependencies_plan_target', table_name='tidb_execution_dependencies')
    op.drop_index(op.f('ix_tidb_execution_dependencies_target_step_id'), table_name='tidb_execution_dependencies')
    op.drop_index(op.f('ix_tidb_execution_dependencies_source_step_id'), table_name='tidb_execution_dependencies')
    op.drop_index(op.f('ix_tidb_execution_dependencies_plan_id'), table_name='tidb_execution_dependencies')
    op.drop_index(op.f('ix_tidb_execution_dependencies_dependency_id'), table_name='tidb_execution_dependencies')
    op.drop_table('tidb_execution_dependencies')
    op.drop_index(op.f('ix_tidb_mission_step_records_state'), table_name='tidb_mission_step_records')
    op.drop_index(op.f('ix_tidb_mission_step_records_tool_id'), table_name='tidb_mission_step_records')
    op.drop_index(op.f('ix_tidb_mission_step_records_capability'), table_name='tidb_mission_step_records')
    op.drop_index(op.f('ix_tidb_mission_step_records_phase_id'), table_name='tidb_mission_step_records')
    op.drop_index(op.f('ix_tidb_mission_step_records_plan_id'), table_name='tidb_mission_step_records')
    op.drop_index(op.f('ix_tidb_mission_step_records_step_id'), table_name='tidb_mission_step_records')
    op.drop_table('tidb_mission_step_records')
    op.drop_index('ix_tidb_mission_phase_records_plan_kind', table_name='tidb_mission_phase_records')
    op.drop_index(op.f('ix_tidb_mission_phase_records_kind'), table_name='tidb_mission_phase_records')
    op.drop_index(op.f('ix_tidb_mission_phase_records_plan_id'), table_name='tidb_mission_phase_records')
    op.drop_index(op.f('ix_tidb_mission_phase_records_phase_id'), table_name='tidb_mission_phase_records')
    op.drop_table('tidb_mission_phase_records')
    op.drop_index('ix_tidb_mission_plan_records_mission_version', table_name='tidb_mission_plan_records')
    op.drop_index(op.f('ix_tidb_mission_plan_records_state'), table_name='tidb_mission_plan_records')
    op.drop_index(op.f('ix_tidb_mission_plan_records_mission_id'), table_name='tidb_mission_plan_records')
    op.drop_index(op.f('ix_tidb_mission_plan_records_plan_id'), table_name='tidb_mission_plan_records')
    op.drop_table('tidb_mission_plan_records')
