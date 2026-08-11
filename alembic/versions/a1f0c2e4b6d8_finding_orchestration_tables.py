"""vulnerability finding orchestration tables

Revision ID: a1f0c2e4b6d8
Revises: 1b3d5f7a9c2e
Create Date: 2026-08-10

Extends the TIDB schema with the Sprint 028 autonomous vulnerability
validation & proof orchestration capability: the canonical finding record,
evidence requirements and gaps, validation attempts, PoC artifacts and replay
records, impact and confidence assessments, evidence conflicts, deduplication
decisions, root-cause records, unknown-behavior profiles, reproduction data,
report-readiness checklists, state transitions and consolidated report
packages.

Security boundary: every table stores canonical findings, redacted evidence
and lifecycle metadata only - never exploit payloads, never credentials,
never unrestricted executable PoC scripts and never out-of-scope request
material.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a1f0c2e4b6d8'
down_revision: str | Sequence[str] | None = '1b3d5f7a9c2e'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('tidb_finding_records',
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('mission_id', sa.String(length=26), nullable=False),
    sa.Column('target_id', sa.String(length=512), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=False),
    sa.Column('vulnerability_class', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('affected_assets', sa.JSON(), nullable=False),
    sa.Column('affected_endpoints', sa.JSON(), nullable=False),
    sa.Column('affected_parameters', sa.JSON(), nullable=False),
    sa.Column('observations', sa.JSON(), nullable=False),
    sa.Column('evidence_refs', sa.JSON(), nullable=False),
    sa.Column('validation_refs', sa.JSON(), nullable=False),
    sa.Column('proof_refs', sa.JSON(), nullable=False),
    sa.Column('impact_refs', sa.JSON(), nullable=False),
    sa.Column('reproduction_refs', sa.JSON(), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('provenance', sa.Text(), nullable=False),
    sa.Column('analysis_version', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_records_asset_id'), 'tidb_finding_records', ['asset_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_records_finding_id'), 'tidb_finding_records', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_records_mission_id'), 'tidb_finding_records', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_records_severity'), 'tidb_finding_records', ['severity'], unique=False)
    op.create_index(op.f('ix_tidb_finding_records_status'), 'tidb_finding_records', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_finding_records_target_id'), 'tidb_finding_records', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_records_vulnerability_class'), 'tidb_finding_records', ['vulnerability_class'], unique=False)
    op.create_index('ix_tidb_finding_records_mission_status', 'tidb_finding_records', ['mission_id', 'status'], unique=False)
    op.create_index('ix_tidb_finding_records_target_class', 'tidb_finding_records', ['target_id', 'vulnerability_class'], unique=False)
    op.create_table('tidb_finding_evidence_requirements',
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('purpose', sa.String(length=32), nullable=False),
    sa.Column('required_kinds', sa.JSON(), nullable=False),
    sa.Column('present_kinds', sa.JSON(), nullable=False),
    sa.Column('missing_kinds', sa.JSON(), nullable=False),
    sa.Column('contradictory_kinds', sa.JSON(), nullable=False),
    sa.Column('sufficiency', sa.String(length=32), nullable=False),
    sa.Column('assessed_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_evidence_requirements_finding_id'), 'tidb_finding_evidence_requirements', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_evidence_requirements_purpose'), 'tidb_finding_evidence_requirements', ['purpose'], unique=False)
    op.create_index(op.f('ix_tidb_finding_evidence_requirements_sufficiency'), 'tidb_finding_evidence_requirements', ['sufficiency'], unique=False)
    op.create_index('ix_tidb_finding_evidence_reqs_finding_purpose', 'tidb_finding_evidence_requirements', ['finding_id', 'purpose'], unique=False)
    op.create_table('tidb_finding_evidence_gaps',
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('purpose', sa.String(length=32), nullable=False),
    sa.Column('requirement_kind', sa.String(length=64), nullable=False),
    sa.Column('gap_kind', sa.String(length=32), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('resolved', sa.Boolean(), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_evidence_gaps_finding_id'), 'tidb_finding_evidence_gaps', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_evidence_gaps_gap_kind'), 'tidb_finding_evidence_gaps', ['gap_kind'], unique=False)
    op.create_index(op.f('ix_tidb_finding_evidence_gaps_purpose'), 'tidb_finding_evidence_gaps', ['purpose'], unique=False)
    op.create_table('tidb_finding_validation_attempts',
    sa.Column('validation_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('plan_id', sa.String(length=26), nullable=False),
    sa.Column('strategy_id', sa.String(length=64), nullable=False),
    sa.Column('tool_id', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('verdict', sa.String(length=32), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('observations', sa.JSON(), nullable=False),
    sa.Column('evidence_ids', sa.JSON(), nullable=False),
    sa.Column('raw_output_hash', sa.String(length=64), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('correlation_id', sa.String(length=26), nullable=False),
    sa.Column('executed_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_validation_attempts_correlation_id'), 'tidb_finding_validation_attempts', ['correlation_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_validation_attempts_finding_id'), 'tidb_finding_validation_attempts', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_validation_attempts_plan_id'), 'tidb_finding_validation_attempts', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_validation_attempts_status'), 'tidb_finding_validation_attempts', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_finding_validation_attempts_strategy_id'), 'tidb_finding_validation_attempts', ['strategy_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_validation_attempts_validation_id'), 'tidb_finding_validation_attempts', ['validation_id'], unique=False)
    op.create_table('tidb_finding_pocs',
    sa.Column('poc_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('format', sa.String(length=64), nullable=False),
    sa.Column('content', sa.Text(), nullable=False),
    sa.Column('lifecycle_state', sa.String(length=32), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('redacted', sa.Boolean(), nullable=False),
    sa.Column('deterministic', sa.Boolean(), nullable=False),
    sa.Column('scope_bound', sa.Boolean(), nullable=False),
    sa.Column('minimal', sa.Boolean(), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_pocs_content_hash'), 'tidb_finding_pocs', ['content_hash'], unique=False)
    op.create_index(op.f('ix_tidb_finding_pocs_finding_id'), 'tidb_finding_pocs', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_pocs_lifecycle_state'), 'tidb_finding_pocs', ['lifecycle_state'], unique=False)
    op.create_index(op.f('ix_tidb_finding_pocs_poc_id'), 'tidb_finding_pocs', ['poc_id'], unique=False)
    op.create_index('ix_tidb_finding_pocs_finding_state', 'tidb_finding_pocs', ['finding_id', 'lifecycle_state'], unique=False)
    op.create_table('tidb_finding_replay_records',
    sa.Column('replay_id', sa.String(length=26), nullable=False),
    sa.Column('poc_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('target', sa.String(length=512), nullable=False),
    sa.Column('scope_verified', sa.Boolean(), nullable=False),
    sa.Column('hypothesis_verified', sa.Boolean(), nullable=False),
    sa.Column('input_hash', sa.String(length=64), nullable=False),
    sa.Column('behavior', sa.Text(), nullable=False),
    sa.Column('evidence_class', sa.String(length=64), nullable=False),
    sa.Column('verdict', sa.String(length=32), nullable=False),
    sa.Column('duration_ms', sa.Integer(), nullable=False),
    sa.Column('captured_evidence_id', sa.String(length=26), nullable=False),
    sa.Column('replayed_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_replay_records_finding_id'), 'tidb_finding_replay_records', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_replay_records_input_hash'), 'tidb_finding_replay_records', ['input_hash'], unique=False)
    op.create_index(op.f('ix_tidb_finding_replay_records_poc_id'), 'tidb_finding_replay_records', ['poc_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_replay_records_replay_id'), 'tidb_finding_replay_records', ['replay_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_replay_records_target'), 'tidb_finding_replay_records', ['target'], unique=False)
    op.create_index(op.f('ix_tidb_finding_replay_records_verdict'), 'tidb_finding_replay_records', ['verdict'], unique=False)
    op.create_table('tidb_finding_impact_assessments',
    sa.Column('assessment_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('dimensions', sa.JSON(), nullable=False),
    sa.Column('evidence_refs', sa.JSON(), nullable=False),
    sa.Column('reasoning', sa.JSON(), nullable=False),
    sa.Column('assessed_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_impact_assessments_assessment_id'), 'tidb_finding_impact_assessments', ['assessment_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_impact_assessments_finding_id'), 'tidb_finding_impact_assessments', ['finding_id'], unique=False)
    op.create_table('tidb_finding_confidence_assessments',
    sa.Column('assessment_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('level', sa.String(length=16), nullable=False),
    sa.Column('factors', sa.JSON(), nullable=False),
    sa.Column('policy_version', sa.String(length=32), nullable=False),
    sa.Column('calculated_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_confidence_assessments_assessment_id'), 'tidb_finding_confidence_assessments', ['assessment_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_confidence_assessments_finding_id'), 'tidb_finding_confidence_assessments', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_confidence_assessments_level'), 'tidb_finding_confidence_assessments', ['level'], unique=False)
    op.create_table('tidb_finding_conflicts',
    sa.Column('conflict_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('evidence_a', sa.JSON(), nullable=True),
    sa.Column('evidence_b', sa.JSON(), nullable=True),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('resolution', sa.JSON(), nullable=False),
    sa.Column('resolution_reason', sa.Text(), nullable=False),
    sa.Column('observed_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_conflicts_conflict_id'), 'tidb_finding_conflicts', ['conflict_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_conflicts_finding_id'), 'tidb_finding_conflicts', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_conflicts_kind'), 'tidb_finding_conflicts', ['kind'], unique=False)
    op.create_index(op.f('ix_tidb_finding_conflicts_status'), 'tidb_finding_conflicts', ['status'], unique=False)
    op.create_table('tidb_finding_dedup_decisions',
    sa.Column('decision_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('matched_finding_id', sa.String(length=26), nullable=False),
    sa.Column('relation', sa.String(length=48), nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('reasons', sa.JSON(), nullable=False),
    sa.Column('decided_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_dedup_decisions_decision_id'), 'tidb_finding_dedup_decisions', ['decision_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_dedup_decisions_finding_id'), 'tidb_finding_dedup_decisions', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_dedup_decisions_key'), 'tidb_finding_dedup_decisions', ['key'], unique=False)
    op.create_index(op.f('ix_tidb_finding_dedup_decisions_matched_finding_id'), 'tidb_finding_dedup_decisions', ['matched_finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_dedup_decisions_relation'), 'tidb_finding_dedup_decisions', ['relation'], unique=False)
    op.create_table('tidb_finding_root_causes',
    sa.Column('root_cause_id', sa.String(length=26), nullable=False),
    sa.Column('mission_id', sa.String(length=26), nullable=False),
    sa.Column('related_finding_ids', sa.JSON(), nullable=False),
    sa.Column('affected_assets', sa.JSON(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('evidence_ids', sa.JSON(), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_root_causes_mission_id'), 'tidb_finding_root_causes', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_root_causes_root_cause_id'), 'tidb_finding_root_causes', ['root_cause_id'], unique=False)
    op.create_table('tidb_finding_unknown_behaviors',
    sa.Column('profile_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('observations', sa.JSON(), nullable=False),
    sa.Column('hypotheses', sa.JSON(), nullable=False),
    sa.Column('classification', sa.String(length=32), nullable=False),
    sa.Column('security_relevance', sa.Boolean(), nullable=False),
    sa.Column('evidence_ids', sa.JSON(), nullable=False),
    sa.Column('classification_reason', sa.Text(), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_unknown_behaviors_classification'), 'tidb_finding_unknown_behaviors', ['classification'], unique=False)
    op.create_index(op.f('ix_tidb_finding_unknown_behaviors_finding_id'), 'tidb_finding_unknown_behaviors', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_unknown_behaviors_profile_id'), 'tidb_finding_unknown_behaviors', ['profile_id'], unique=False)
    op.create_table('tidb_finding_reproductions',
    sa.Column('reproduction_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('request', sa.Text(), nullable=False),
    sa.Column('method', sa.String(length=16), nullable=False),
    sa.Column('headers', sa.JSON(), nullable=False),
    sa.Column('cookies', sa.JSON(), nullable=False),
    sa.Column('parameters', sa.JSON(), nullable=False),
    sa.Column('payload_reference', sa.String(length=255), nullable=False),
    sa.Column('environment', sa.String(length=255), nullable=False),
    sa.Column('response_characteristics', sa.Text(), nullable=False),
    sa.Column('timing', sa.String(length=128), nullable=False),
    sa.Column('callback_evidence', sa.Text(), nullable=False),
    sa.Column('expected_result', sa.Text(), nullable=False),
    sa.Column('actual_result', sa.Text(), nullable=False),
    sa.Column('redacted', sa.Boolean(), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_reproductions_finding_id'), 'tidb_finding_reproductions', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_reproductions_reproduction_id'), 'tidb_finding_reproductions', ['reproduction_id'], unique=False)
    op.create_table('tidb_finding_report_checklists',
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('checks', sa.JSON(), nullable=False),
    sa.Column('complete', sa.Boolean(), nullable=False),
    sa.Column('reportable', sa.Boolean(), nullable=False),
    sa.Column('assessed_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_report_checklists_finding_id'), 'tidb_finding_report_checklists', ['finding_id'], unique=False)
    op.create_table('tidb_finding_state_transitions_v2',
    sa.Column('transition_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('from_state', sa.String(length=32), nullable=False),
    sa.Column('to_state', sa.String(length=32), nullable=False),
    sa.Column('allowed', sa.Boolean(), nullable=False),
    sa.Column('missing_purposes', sa.JSON(), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('transitioned_at', sa.String(length=32), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_state_transitions_v2_finding_id'), 'tidb_finding_state_transitions_v2', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_state_transitions_v2_to_state'), 'tidb_finding_state_transitions_v2', ['to_state'], unique=False)
    op.create_index(op.f('ix_tidb_finding_state_transitions_v2_transition_id'), 'tidb_finding_state_transitions_v2', ['transition_id'], unique=False)
    op.create_table('tidb_finding_package_records',
    sa.Column('package_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('finding_state', sa.String(length=32), nullable=False),
    sa.Column('package_json', sa.JSON(), nullable=False),
    sa.Column('checklist_id', sa.String(length=26), nullable=False),
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
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_finding_package_records_finding_id'), 'tidb_finding_package_records', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_finding_package_records_finding_state'), 'tidb_finding_package_records', ['finding_state'], unique=False)
    op.create_index(op.f('ix_tidb_finding_package_records_package_id'), 'tidb_finding_package_records', ['package_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_finding_package_records_package_id'), table_name='tidb_finding_package_records')
    op.drop_index(op.f('ix_tidb_finding_package_records_finding_state'), table_name='tidb_finding_package_records')
    op.drop_index(op.f('ix_tidb_finding_package_records_finding_id'), table_name='tidb_finding_package_records')
    op.drop_table('tidb_finding_package_records')
    op.drop_index(op.f('ix_tidb_finding_state_transitions_v2_transition_id'), table_name='tidb_finding_state_transitions_v2')
    op.drop_index(op.f('ix_tidb_finding_state_transitions_v2_to_state'), table_name='tidb_finding_state_transitions_v2')
    op.drop_index(op.f('ix_tidb_finding_state_transitions_v2_finding_id'), table_name='tidb_finding_state_transitions_v2')
    op.drop_table('tidb_finding_state_transitions_v2')
    op.drop_index(op.f('ix_tidb_finding_report_checklists_finding_id'), table_name='tidb_finding_report_checklists')
    op.drop_table('tidb_finding_report_checklists')
    op.drop_index(op.f('ix_tidb_finding_reproductions_reproduction_id'), table_name='tidb_finding_reproductions')
    op.drop_index(op.f('ix_tidb_finding_reproductions_finding_id'), table_name='tidb_finding_reproductions')
    op.drop_table('tidb_finding_reproductions')
    op.drop_index(op.f('ix_tidb_finding_unknown_behaviors_profile_id'), table_name='tidb_finding_unknown_behaviors')
    op.drop_index(op.f('ix_tidb_finding_unknown_behaviors_finding_id'), table_name='tidb_finding_unknown_behaviors')
    op.drop_index(op.f('ix_tidb_finding_unknown_behaviors_classification'), table_name='tidb_finding_unknown_behaviors')
    op.drop_table('tidb_finding_unknown_behaviors')
    op.drop_index(op.f('ix_tidb_finding_root_causes_root_cause_id'), table_name='tidb_finding_root_causes')
    op.drop_index(op.f('ix_tidb_finding_root_causes_mission_id'), table_name='tidb_finding_root_causes')
    op.drop_table('tidb_finding_root_causes')
    op.drop_index(op.f('ix_tidb_finding_dedup_decisions_relation'), table_name='tidb_finding_dedup_decisions')
    op.drop_index(op.f('ix_tidb_finding_dedup_decisions_matched_finding_id'), table_name='tidb_finding_dedup_decisions')
    op.drop_index(op.f('ix_tidb_finding_dedup_decisions_key'), table_name='tidb_finding_dedup_decisions')
    op.drop_index(op.f('ix_tidb_finding_dedup_decisions_finding_id'), table_name='tidb_finding_dedup_decisions')
    op.drop_index(op.f('ix_tidb_finding_dedup_decisions_decision_id'), table_name='tidb_finding_dedup_decisions')
    op.drop_table('tidb_finding_dedup_decisions')
    op.drop_index(op.f('ix_tidb_finding_conflicts_status'), table_name='tidb_finding_conflicts')
    op.drop_index(op.f('ix_tidb_finding_conflicts_kind'), table_name='tidb_finding_conflicts')
    op.drop_index(op.f('ix_tidb_finding_conflicts_finding_id'), table_name='tidb_finding_conflicts')
    op.drop_index(op.f('ix_tidb_finding_conflicts_conflict_id'), table_name='tidb_finding_conflicts')
    op.drop_table('tidb_finding_conflicts')
    op.drop_index(op.f('ix_tidb_finding_confidence_assessments_level'), table_name='tidb_finding_confidence_assessments')
    op.drop_index(op.f('ix_tidb_finding_confidence_assessments_finding_id'), table_name='tidb_finding_confidence_assessments')
    op.drop_index(op.f('ix_tidb_finding_confidence_assessments_assessment_id'), table_name='tidb_finding_confidence_assessments')
    op.drop_table('tidb_finding_confidence_assessments')
    op.drop_index(op.f('ix_tidb_finding_impact_assessments_finding_id'), table_name='tidb_finding_impact_assessments')
    op.drop_index(op.f('ix_tidb_finding_impact_assessments_assessment_id'), table_name='tidb_finding_impact_assessments')
    op.drop_table('tidb_finding_impact_assessments')
    op.drop_index(op.f('ix_tidb_finding_replay_records_verdict'), table_name='tidb_finding_replay_records')
    op.drop_index(op.f('ix_tidb_finding_replay_records_target'), table_name='tidb_finding_replay_records')
    op.drop_index(op.f('ix_tidb_finding_replay_records_replay_id'), table_name='tidb_finding_replay_records')
    op.drop_index(op.f('ix_tidb_finding_replay_records_poc_id'), table_name='tidb_finding_replay_records')
    op.drop_index(op.f('ix_tidb_finding_replay_records_input_hash'), table_name='tidb_finding_replay_records')
    op.drop_index(op.f('ix_tidb_finding_replay_records_finding_id'), table_name='tidb_finding_replay_records')
    op.drop_table('tidb_finding_replay_records')
    op.drop_index('ix_tidb_finding_pocs_finding_state', table_name='tidb_finding_pocs')
    op.drop_index(op.f('ix_tidb_finding_pocs_poc_id'), table_name='tidb_finding_pocs')
    op.drop_index(op.f('ix_tidb_finding_pocs_lifecycle_state'), table_name='tidb_finding_pocs')
    op.drop_index(op.f('ix_tidb_finding_pocs_finding_id'), table_name='tidb_finding_pocs')
    op.drop_index(op.f('ix_tidb_finding_pocs_content_hash'), table_name='tidb_finding_pocs')
    op.drop_table('tidb_finding_pocs')
    op.drop_index(op.f('ix_tidb_finding_validation_attempts_validation_id'), table_name='tidb_finding_validation_attempts')
    op.drop_index(op.f('ix_tidb_finding_validation_attempts_strategy_id'), table_name='tidb_finding_validation_attempts')
    op.drop_index(op.f('ix_tidb_finding_validation_attempts_status'), table_name='tidb_finding_validation_attempts')
    op.drop_index(op.f('ix_tidb_finding_validation_attempts_plan_id'), table_name='tidb_finding_validation_attempts')
    op.drop_index(op.f('ix_tidb_finding_validation_attempts_finding_id'), table_name='tidb_finding_validation_attempts')
    op.drop_index(op.f('ix_tidb_finding_validation_attempts_correlation_id'), table_name='tidb_finding_validation_attempts')
    op.drop_table('tidb_finding_validation_attempts')
    op.drop_index(op.f('ix_tidb_finding_evidence_gaps_purpose'), table_name='tidb_finding_evidence_gaps')
    op.drop_index(op.f('ix_tidb_finding_evidence_gaps_gap_kind'), table_name='tidb_finding_evidence_gaps')
    op.drop_index(op.f('ix_tidb_finding_evidence_gaps_finding_id'), table_name='tidb_finding_evidence_gaps')
    op.drop_table('tidb_finding_evidence_gaps')
    op.drop_index('ix_tidb_finding_evidence_reqs_finding_purpose', table_name='tidb_finding_evidence_requirements')
    op.drop_index(op.f('ix_tidb_finding_evidence_requirements_sufficiency'), table_name='tidb_finding_evidence_requirements')
    op.drop_index(op.f('ix_tidb_finding_evidence_requirements_purpose'), table_name='tidb_finding_evidence_requirements')
    op.drop_index(op.f('ix_tidb_finding_evidence_requirements_finding_id'), table_name='tidb_finding_evidence_requirements')
    op.drop_table('tidb_finding_evidence_requirements')
    op.drop_index('ix_tidb_finding_records_target_class', table_name='tidb_finding_records')
    op.drop_index('ix_tidb_finding_records_mission_status', table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_vulnerability_class'), table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_target_id'), table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_status'), table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_severity'), table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_mission_id'), table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_finding_id'), table_name='tidb_finding_records')
    op.drop_index(op.f('ix_tidb_finding_records_asset_id'), table_name='tidb_finding_records')
    op.drop_table('tidb_finding_records')
