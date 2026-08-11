"""professional reporting intelligence tables

Revision ID: b2e3f5a7c9d1
Revises: a1f0c2e4b6d8
Create Date: 2026-08-10

Extends the TIDB schema with the Sprint 029 professional finding
intelligence & reporting capability: report metadata, immutable report
versions, data-driven report templates and template versions, claim records,
QA results, evidence snapshots, report packages, remediation plans, retest
plans and submission state.

Security boundary: every table stores canonical, redacted report data only -
never credentials, never exploit payloads, never out-of-scope request
material. Report exports are immutable/versioned.
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b2e3f5a7c9d1'
down_revision: str | Sequence[str] | None = 'a1f0c2e4b6d8'
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
    op.create_table('tidb_report_records',
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('mission_id', sa.String(length=26), nullable=False),
    sa.Column('target_id', sa.String(length=512), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('template', sa.String(length=48), nullable=False),
    sa.Column('template_version', sa.String(length=32), nullable=False),
    sa.Column('report_schema_version', sa.String(length=32), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('generator_version', sa.String(length=32), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_records_report_id'), 'tidb_report_records', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_records_finding_id'), 'tidb_report_records', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_records_mission_id'), 'tidb_report_records', ['mission_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_records_target_id'), 'tidb_report_records', ['target_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_records_template'), 'tidb_report_records', ['template'], unique=False)
    op.create_index(op.f('ix_tidb_report_records_status'), 'tidb_report_records', ['status'], unique=False)
    op.create_index('ix_tidb_report_records_finding_status', 'tidb_report_records', ['finding_id', 'status'], unique=False)
    op.create_index('ix_tidb_report_records_mission_status', 'tidb_report_records', ['mission_id', 'status'], unique=False)
    op.create_table('tidb_report_versions',
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('template_version', sa.String(length=32), nullable=False),
    sa.Column('report_schema_version', sa.String(length=32), nullable=False),
    sa.Column('generated_at', sa.String(length=32), nullable=False),
    sa.Column('generator_version', sa.String(length=32), nullable=False),
    sa.Column('source_snapshot', sa.String(length=64), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_versions_report_id'), 'tidb_report_versions', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_versions_finding_id'), 'tidb_report_versions', ['finding_id'], unique=False)
    op.create_index('ix_tidb_report_versions_report_version', 'tidb_report_versions', ['report_id', 'version'], unique=False)
    op.create_table('tidb_report_templates',
    sa.Column('template_id', sa.String(length=26), nullable=False),
    sa.Column('kind', sa.String(length=48), nullable=False),
    sa.Column('template_version', sa.String(length=32), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('sections', sa.JSON(), nullable=False),
    sa.Column('template_schema_version', sa.String(length=32), nullable=False),
    sa.Column('locale', sa.String(length=8), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_templates_template_id'), 'tidb_report_templates', ['template_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_templates_kind'), 'tidb_report_templates', ['kind'], unique=False)
    op.create_table('tidb_report_template_versions',
    sa.Column('template_id', sa.String(length=26), nullable=False),
    sa.Column('kind', sa.String(length=48), nullable=False),
    sa.Column('template_json', sa.JSON(), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_template_versions_template_id'), 'tidb_report_template_versions', ['template_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_template_versions_kind'), 'tidb_report_template_versions', ['kind'], unique=False)
    op.create_table('tidb_report_claims',
    sa.Column('claim_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('claim_text', sa.Text(), nullable=False),
    sa.Column('source_refs', sa.JSON(), nullable=False),
    sa.Column('claim_type', sa.String(length=48), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=False),
    sa.Column('generated_by', sa.String(length=64), nullable=False),
    sa.Column('verification_state', sa.String(length=32), nullable=False),
    sa.Column('verification_detail', sa.Text(), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_claims_claim_id'), 'tidb_report_claims', ['claim_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_claims_report_id'), 'tidb_report_claims', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_claims_finding_id'), 'tidb_report_claims', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_claims_claim_type'), 'tidb_report_claims', ['claim_type'], unique=False)
    op.create_index(op.f('ix_tidb_report_claims_verification_state'), 'tidb_report_claims', ['verification_state'], unique=False)
    op.create_index('ix_tidb_report_claims_report_state', 'tidb_report_claims', ['report_id', 'verification_state'], unique=False)
    op.create_table('tidb_report_qa_results',
    sa.Column('qa_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=False),
    sa.Column('checks', sa.JSON(), nullable=False),
    sa.Column('blocked', sa.Boolean(), nullable=False),
    sa.Column('reasons', sa.JSON(), nullable=False),
    sa.Column('checked_at', sa.String(length=32), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_qa_results_qa_id'), 'tidb_report_qa_results', ['qa_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_qa_results_report_id'), 'tidb_report_qa_results', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_qa_results_verdict'), 'tidb_report_qa_results', ['verdict'], unique=False)
    op.create_table('tidb_report_evidence_snapshots',
    sa.Column('snapshot_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('finding_hash', sa.String(length=64), nullable=False),
    sa.Column('evidence_hash', sa.String(length=64), nullable=False),
    sa.Column('captured_at', sa.String(length=32), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_evidence_snapshots_snapshot_id'), 'tidb_report_evidence_snapshots', ['snapshot_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_evidence_snapshots_report_id'), 'tidb_report_evidence_snapshots', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_evidence_snapshots_finding_id'), 'tidb_report_evidence_snapshots', ['finding_id'], unique=False)
    op.create_table('tidb_report_packages',
    sa.Column('package_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('document_json', sa.JSON(), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('generated_at', sa.String(length=32), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_packages_package_id'), 'tidb_report_packages', ['package_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_packages_report_id'), 'tidb_report_packages', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_packages_finding_id'), 'tidb_report_packages', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_packages_status'), 'tidb_report_packages', ['status'], unique=False)
    op.create_table('tidb_report_remediation_plans',
    sa.Column('plan_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('root_cause_id', sa.String(length=26), nullable=False),
    sa.Column('plan_json', sa.JSON(), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_remediation_plans_plan_id'), 'tidb_report_remediation_plans', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_remediation_plans_finding_id'), 'tidb_report_remediation_plans', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_remediation_plans_report_id'), 'tidb_report_remediation_plans', ['report_id'], unique=False)
    op.create_table('tidb_report_retest_plans',
    sa.Column('plan_id', sa.String(length=26), nullable=False),
    sa.Column('finding_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('state', sa.String(length=32), nullable=False),
    sa.Column('plan_json', sa.JSON(), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_retest_plans_plan_id'), 'tidb_report_retest_plans', ['plan_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_retest_plans_finding_id'), 'tidb_report_retest_plans', ['finding_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_retest_plans_report_id'), 'tidb_report_retest_plans', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_retest_plans_state'), 'tidb_report_retest_plans', ['state'], unique=False)
    op.create_table('tidb_report_submissions',
    sa.Column('submission_id', sa.String(length=26), nullable=False),
    sa.Column('report_id', sa.String(length=26), nullable=False),
    sa.Column('state', sa.String(length=32), nullable=False),
    sa.Column('submitted_at', sa.String(length=32), nullable=False),
    sa.Column('target', sa.String(length=512), nullable=False),
    sa.Column('evidence_snapshot_id', sa.String(length=26), nullable=False),
    *_envelope(),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_tidb_report_submissions_submission_id'), 'tidb_report_submissions', ['submission_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_submissions_report_id'), 'tidb_report_submissions', ['report_id'], unique=False)
    op.create_index(op.f('ix_tidb_report_submissions_state'), 'tidb_report_submissions', ['state'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_tidb_report_submissions_state'), table_name='tidb_report_submissions')
    op.drop_index(op.f('ix_tidb_report_submissions_report_id'), table_name='tidb_report_submissions')
    op.drop_index(op.f('ix_tidb_report_submissions_submission_id'), table_name='tidb_report_submissions')
    op.drop_table('tidb_report_submissions')
    op.drop_index(op.f('ix_tidb_report_retest_plans_state'), table_name='tidb_report_retest_plans')
    op.drop_index(op.f('ix_tidb_report_retest_plans_report_id'), table_name='tidb_report_retest_plans')
    op.drop_index(op.f('ix_tidb_report_retest_plans_finding_id'), table_name='tidb_report_retest_plans')
    op.drop_index(op.f('ix_tidb_report_retest_plans_plan_id'), table_name='tidb_report_retest_plans')
    op.drop_table('tidb_report_retest_plans')
    op.drop_index(op.f('ix_tidb_report_remediation_plans_report_id'), table_name='tidb_report_remediation_plans')
    op.drop_index(op.f('ix_tidb_report_remediation_plans_finding_id'), table_name='tidb_report_remediation_plans')
    op.drop_index(op.f('ix_tidb_report_remediation_plans_plan_id'), table_name='tidb_report_remediation_plans')
    op.drop_table('tidb_report_remediation_plans')
    op.drop_index(op.f('ix_tidb_report_packages_status'), table_name='tidb_report_packages')
    op.drop_index(op.f('ix_tidb_report_packages_finding_id'), table_name='tidb_report_packages')
    op.drop_index(op.f('ix_tidb_report_packages_report_id'), table_name='tidb_report_packages')
    op.drop_index(op.f('ix_tidb_report_packages_package_id'), table_name='tidb_report_packages')
    op.drop_table('tidb_report_packages')
    op.drop_index(op.f('ix_tidb_report_evidence_snapshots_finding_id'), table_name='tidb_report_evidence_snapshots')
    op.drop_index(op.f('ix_tidb_report_evidence_snapshots_report_id'), table_name='tidb_report_evidence_snapshots')
    op.drop_index(op.f('ix_tidb_report_evidence_snapshots_snapshot_id'), table_name='tidb_report_evidence_snapshots')
    op.drop_table('tidb_report_evidence_snapshots')
    op.drop_index(op.f('ix_tidb_report_qa_results_verdict'), table_name='tidb_report_qa_results')
    op.drop_index(op.f('ix_tidb_report_qa_results_report_id'), table_name='tidb_report_qa_results')
    op.drop_index(op.f('ix_tidb_report_qa_results_qa_id'), table_name='tidb_report_qa_results')
    op.drop_table('tidb_report_qa_results')
    op.drop_index('ix_tidb_report_claims_report_state', table_name='tidb_report_claims')
    op.drop_index(op.f('ix_tidb_report_claims_verification_state'), table_name='tidb_report_claims')
    op.drop_index(op.f('ix_tidb_report_claims_claim_type'), table_name='tidb_report_claims')
    op.drop_index(op.f('ix_tidb_report_claims_finding_id'), table_name='tidb_report_claims')
    op.drop_index(op.f('ix_tidb_report_claims_report_id'), table_name='tidb_report_claims')
    op.drop_index(op.f('ix_tidb_report_claims_claim_id'), table_name='tidb_report_claims')
    op.drop_table('tidb_report_claims')
    op.drop_index(op.f('ix_tidb_report_template_versions_kind'), table_name='tidb_report_template_versions')
    op.drop_index(op.f('ix_tidb_report_template_versions_template_id'), table_name='tidb_report_template_versions')
    op.drop_table('tidb_report_template_versions')
    op.drop_index(op.f('ix_tidb_report_templates_kind'), table_name='tidb_report_templates')
    op.drop_index(op.f('ix_tidb_report_templates_template_id'), table_name='tidb_report_templates')
    op.drop_table('tidb_report_templates')
    op.drop_index('ix_tidb_report_versions_report_version', table_name='tidb_report_versions')
    op.drop_index(op.f('ix_tidb_report_versions_finding_id'), table_name='tidb_report_versions')
    op.drop_index(op.f('ix_tidb_report_versions_report_id'), table_name='tidb_report_versions')
    op.drop_table('tidb_report_versions')
    op.drop_index('ix_tidb_report_records_mission_status', table_name='tidb_report_records')
    op.drop_index('ix_tidb_report_records_finding_status', table_name='tidb_report_records')
    op.drop_index(op.f('ix_tidb_report_records_status'), table_name='tidb_report_records')
    op.drop_index(op.f('ix_tidb_report_records_template'), table_name='tidb_report_records')
    op.drop_index(op.f('ix_tidb_report_records_target_id'), table_name='tidb_report_records')
    op.drop_index(op.f('ix_tidb_report_records_mission_id'), table_name='tidb_report_records')
    op.drop_index(op.f('ix_tidb_report_records_finding_id'), table_name='tidb_report_records')
    op.drop_index(op.f('ix_tidb_report_records_report_id'), table_name='tidb_report_records')
    op.drop_table('tidb_report_records')
