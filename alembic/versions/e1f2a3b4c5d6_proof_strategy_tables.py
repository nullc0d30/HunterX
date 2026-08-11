"""proof strategy library and validator tables

Revision ID: e1f2a3b4c5d6
Revises: d4a5b6c7e8f0
Create Date: 2026-08-10

Extends the TIDB schema with the Sprint 022 vulnerability proof strategy
library: proof strategies and their versions, strategy requirements, evidence
rules, tool requirements, strategy candidates (novel), proof validation results
and manual proof instructions.

Security boundary: every table stores strategy contracts, canonical evidence
rules and validation results only - never exploit payloads, never credentials,
never unrestricted executable PoC scripts and never out-of-scope request
material.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e1f2a3b4c5d6'
down_revision: str | Sequence[str] | None = 'd4a5b6c7e8f0'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('tidb_proof_strategies',
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('strategy_version', sa.String(length=32), nullable=False),
    sa.Column('vulnerability_class', sa.String(length=64), nullable=False),
    sa.Column('security_property', sa.Text, nullable=False),
    sa.Column('description', sa.Text, nullable=False),
    sa.Column('preconditions', sa.JSON(), nullable=False),
    sa.Column('required_inputs', sa.JSON(), nullable=False),
    sa.Column('allowed_actions', sa.JSON(), nullable=False),
    sa.Column('forbidden_actions', sa.JSON(), nullable=False),
    sa.Column('required_evidence', sa.JSON(), nullable=False),
    sa.Column('optional_evidence', sa.JSON(), nullable=False),
    sa.Column('expected_observations', sa.JSON(), nullable=False),
    sa.Column('negative_observations', sa.JSON(), nullable=False),
    sa.Column('inconclusive_conditions', sa.JSON(), nullable=False),
    sa.Column('confirmation_conditions', sa.JSON(), nullable=False),
    sa.Column('replay_requirements', sa.JSON(), nullable=False),
    sa.Column('impact_requirements', sa.JSON(), nullable=False),
    sa.Column('required_capabilities', sa.JSON(), nullable=False),
    sa.Column('preferred_tools', sa.JSON(), nullable=False),
    sa.Column('fallback_strategies', sa.JSON(), nullable=False),
    sa.Column('safety_class', sa.String(length=32), nullable=False),
    sa.Column('scope_requirements', sa.JSON(), nullable=False),
    sa.Column('confidence_policy', sa.String(length=128), nullable=False),
    sa.Column('stop_conditions', sa.JSON(), nullable=False),
    sa.Column('abort_conditions', sa.JSON(), nullable=False),
    sa.Column('provenance', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('permits_confirmation', sa.Boolean, nullable=False),
    sa.Column('reportable', sa.Boolean, nullable=False),
    sa.Column('execution', sa.String(length=32), nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_strategies_strategy_id'), 'tidb_proof_strategies', ['strategy_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategies_status'), 'tidb_proof_strategies', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategies_vulnerability_class'), 'tidb_proof_strategies', ['vulnerability_class'], unique=False)
    op.create_table('tidb_proof_strategy_versions',
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('strategy_version', sa.String(length=32), nullable=False),
    sa.Column('vulnerability_class', sa.String(length=64), nullable=False),
    sa.Column('strategy_checksum', sa.String(length=64), nullable=False),
    sa.Column('reason', sa.Text, nullable=False),
    sa.Column('previous_version', sa.String(length=32), nullable=False),
    sa.Column('superseded_by', sa.String(length=32), nullable=False),
    sa.Column('registered_at', sa.String(length=32), nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_strategy_versions_strategy_id'), 'tidb_proof_strategy_versions', ['strategy_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategy_versions_vulnerability_class'), 'tidb_proof_strategy_versions', ['vulnerability_class'], unique=False)
    op.create_table('tidb_proof_strategy_requirements',
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('strategy_version', sa.String(length=32), nullable=False),
    sa.Column('requirement_type', sa.String(length=32), nullable=False),
    sa.Column('requirement', sa.Text, nullable=False),
    sa.Column('required', sa.Boolean, nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_strategy_requirements_requirement_type'), 'tidb_proof_strategy_requirements', ['requirement_type'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategy_requirements_strategy_id'), 'tidb_proof_strategy_requirements', ['strategy_id'], unique=False)
    op.create_table('tidb_proof_strategy_evidence_rules',
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('strategy_version', sa.String(length=32), nullable=False),
    sa.Column('rule_type', sa.String(length=32), nullable=False),
    sa.Column('evidence_kind', sa.String(length=64), nullable=False),
    sa.Column('confirmation_rule', sa.Text, nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_strategy_evidence_rules_rule_type'), 'tidb_proof_strategy_evidence_rules', ['rule_type'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategy_evidence_rules_strategy_id'), 'tidb_proof_strategy_evidence_rules', ['strategy_id'], unique=False)
    op.create_table('tidb_proof_strategy_tool_requirements',
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('strategy_version', sa.String(length=32), nullable=False),
    sa.Column('capability', sa.String(length=64), nullable=False),
    sa.Column('sdk_capabilities', sa.JSON(), nullable=False),
    sa.Column('preferred_tool', sa.String(length=128), nullable=False),
    sa.Column('optional', sa.Boolean, nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_strategy_tool_requirements_strategy_id'), 'tidb_proof_strategy_tool_requirements', ['strategy_id'], unique=False)
    op.create_table('tidb_proof_strategy_candidates',
    sa.Column('candidate_id', sa.String(length=26), nullable=False),
    sa.Column('vulnerability_class', sa.String(length=64), nullable=False),
    sa.Column('observed_behavior', sa.Text, nullable=False),
    sa.Column('evidence', sa.JSON(), nullable=False),
    sa.Column('proposed_strategy_id', sa.String(length=128), nullable=False),
    sa.Column('proposed_strategy', sa.JSON(), nullable=False),
    sa.Column('reasoning', sa.Text, nullable=False),
    sa.Column('source_findings', sa.JSON(), nullable=False),
    sa.Column('confidence', sa.Float, nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('review_required', sa.Boolean, nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_strategy_candidates_candidate_id'), 'tidb_proof_strategy_candidates', ['candidate_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategy_candidates_status'), 'tidb_proof_strategy_candidates', ['status'], unique=False)
    op.create_index(op.f('ix_tidb_proof_strategy_candidates_vulnerability_class'), 'tidb_proof_strategy_candidates', ['vulnerability_class'], unique=False)
    op.create_table('tidb_proof_validation_results',
    sa.Column('proof_id', sa.String(length=26), nullable=False),
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('strategy_version', sa.String(length=32), nullable=False),
    sa.Column('verdict', sa.String(length=32), nullable=False),
    sa.Column('score', sa.Float, nullable=False),
    sa.Column('proof_quality_level', sa.String(length=32), nullable=False),
    sa.Column('required_evidence', sa.JSON(), nullable=False),
    sa.Column('present_evidence', sa.JSON(), nullable=False),
    sa.Column('missing_evidence', sa.JSON(), nullable=False),
    sa.Column('contradictory_evidence', sa.JSON(), nullable=False),
    sa.Column('disqualifying_evidence', sa.JSON(), nullable=False),
    sa.Column('scope_result', sa.JSON(), nullable=False),
    sa.Column('safety_result', sa.JSON(), nullable=False),
    sa.Column('replay_result', sa.JSON(), nullable=False),
    sa.Column('impact_result', sa.JSON(), nullable=False),
    sa.Column('reproducibility_result', sa.JSON(), nullable=False),
    sa.Column('evidence_covered', sa.JSON(), nullable=False),
    sa.Column('evidence_contract_ok', sa.Boolean, nullable=False),
    sa.Column('reasoning', sa.JSON(), nullable=False),
    sa.Column('recommendations', sa.JSON(), nullable=False),
    sa.Column('validator_version', sa.String(length=32), nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_validation_results_verdict'), 'tidb_proof_validation_results', ['verdict'], unique=False)
    op.create_index(op.f('ix_tidb_proof_validation_results_proof_id'), 'tidb_proof_validation_results', ['proof_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_validation_results_strategy_id'), 'tidb_proof_validation_results', ['strategy_id'], unique=False)
    op.create_table('tidb_proof_manual_instructions',
    sa.Column('instruction_id', sa.String(length=26), nullable=False),
    sa.Column('proof_id', sa.String(length=26), nullable=False),
    sa.Column('strategy_id', sa.String(length=128), nullable=False),
    sa.Column('mission_id', sa.String(length=26), nullable=False),
    sa.Column('target_id', sa.String(length=512), nullable=False),
    sa.Column('asset_id', sa.String(length=512), nullable=False),
    sa.Column('objective', sa.Text, nullable=False),
    sa.Column('preconditions', sa.JSON(), nullable=False),
    sa.Column('steps', sa.JSON(), nullable=False),
    sa.Column('expected_observation', sa.Text, nullable=False),
    sa.Column('evidence_to_capture', sa.JSON(), nullable=False),
    sa.Column('safety_notes', sa.JSON(), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('completion_criteria', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('id', sa.String(length=26), nullable=False),
    sa.Column('created_at', sa.String(length=32), nullable=False),
    sa.Column('updated_at', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.String(length=32), nullable=True),
    sa.Column('last_seen', sa.String(length=32), nullable=True),
    sa.Column('version', sa.Integer, nullable=False),
    sa.Column('revision', sa.Integer, nullable=False),
    sa.Column('schema_version', sa.Integer, nullable=False),
    sa.Column('deleted_at', sa.String(length=32), nullable=True),
    sa.Column('meta', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_proof_manual_instructions_instruction_id'), 'tidb_proof_manual_instructions', ['instruction_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_manual_instructions_proof_id'), 'tidb_proof_manual_instructions', ['proof_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_manual_instructions_strategy_id'), 'tidb_proof_manual_instructions', ['strategy_id'], unique=False)
    op.create_index(op.f('ix_tidb_proof_manual_instructions_mission_id'), 'tidb_proof_manual_instructions', ['mission_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_proof_manual_instructions_mission_id'), table_name='tidb_proof_manual_instructions')
    op.drop_index(op.f('ix_tidb_proof_manual_instructions_strategy_id'), table_name='tidb_proof_manual_instructions')
    op.drop_index(op.f('ix_tidb_proof_manual_instructions_proof_id'), table_name='tidb_proof_manual_instructions')
    op.drop_index(op.f('ix_tidb_proof_manual_instructions_instruction_id'), table_name='tidb_proof_manual_instructions')
    op.drop_table('tidb_proof_manual_instructions')
    op.drop_index(op.f('ix_tidb_proof_validation_results_strategy_id'), table_name='tidb_proof_validation_results')
    op.drop_index(op.f('ix_tidb_proof_validation_results_proof_id'), table_name='tidb_proof_validation_results')
    op.drop_index(op.f('ix_tidb_proof_validation_results_verdict'), table_name='tidb_proof_validation_results')
    op.drop_table('tidb_proof_validation_results')
    op.drop_index(op.f('ix_tidb_proof_strategy_candidates_vulnerability_class'), table_name='tidb_proof_strategy_candidates')
    op.drop_index(op.f('ix_tidb_proof_strategy_candidates_status'), table_name='tidb_proof_strategy_candidates')
    op.drop_index(op.f('ix_tidb_proof_strategy_candidates_candidate_id'), table_name='tidb_proof_strategy_candidates')
    op.drop_table('tidb_proof_strategy_candidates')
    op.drop_index(op.f('ix_tidb_proof_strategy_tool_requirements_strategy_id'), table_name='tidb_proof_strategy_tool_requirements')
    op.drop_table('tidb_proof_strategy_tool_requirements')
    op.drop_index(op.f('ix_tidb_proof_strategy_evidence_rules_strategy_id'), table_name='tidb_proof_strategy_evidence_rules')
    op.drop_index(op.f('ix_tidb_proof_strategy_evidence_rules_rule_type'), table_name='tidb_proof_strategy_evidence_rules')
    op.drop_table('tidb_proof_strategy_evidence_rules')
    op.drop_index(op.f('ix_tidb_proof_strategy_requirements_strategy_id'), table_name='tidb_proof_strategy_requirements')
    op.drop_index(op.f('ix_tidb_proof_strategy_requirements_requirement_type'), table_name='tidb_proof_strategy_requirements')
    op.drop_table('tidb_proof_strategy_requirements')
    op.drop_index(op.f('ix_tidb_proof_strategy_versions_vulnerability_class'), table_name='tidb_proof_strategy_versions')
    op.drop_index(op.f('ix_tidb_proof_strategy_versions_strategy_id'), table_name='tidb_proof_strategy_versions')
    op.drop_table('tidb_proof_strategy_versions')
    op.drop_index(op.f('ix_tidb_proof_strategies_vulnerability_class'), table_name='tidb_proof_strategies')
    op.drop_index(op.f('ix_tidb_proof_strategies_status'), table_name='tidb_proof_strategies')
    op.drop_index(op.f('ix_tidb_proof_strategies_strategy_id'), table_name='tidb_proof_strategies')
    op.drop_table('tidb_proof_strategies')
