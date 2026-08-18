"""Initial ComplianceIQ persistence schema (Phase 4).

Revision ID: 0001
Revises: (none — this is the base revision)

Creates the six tables that make a scan durable:

* ``scans``              — one scan execution, plus its denormalized summary counts
* ``scan_errors``        — structured partial failures for a scan
* ``resource_snapshots`` — what each resource looked like during that scan
* ``finding_snapshots``  — each finding as observed in that scan
* ``logical_findings``   — the cross-scan lifecycle of one security issue
* ``rule_versions``      — rule metadata, stored once per (rule_id, version)

Table order matters: ``scans`` is created before the three tables that
carry a ``scan_key`` foreign key into it, and ``downgrade`` drops them in
the reverse order. PostgreSQL would otherwise reject the DDL outright,
which is a good failure — but only if it happens in review, not in
production.

Notes for reviewers:

* **Enums are TEXT + CHECK, not native ENUM types.** ``CloudProvider`` is
  explicitly expected to grow (GCP), and extending a native enum requires
  ``ALTER TYPE``, which takes a lock. A CHECK constraint is replaced with
  an ordinary ``ALTER TABLE`` in a future migration.
* **No ``server_default`` on the count/JSONB columns.** Defaults are
  applied in Python by the ORM models. Keeping them off the server means
  the schema states exactly one truth, and the parity test in
  tests/integration/persistence/test_migrations.py can assert that this
  migration and the ORM models describe the same database.
* **Every index leads with ``tenant_id``**, because every query is
  tenant-scoped and a composite index only serves a query that uses its
  leading column.

The body was produced with ``alembic revision --autogenerate`` and then
reviewed line by line against
infrastructure/persistence/postgres/models/tables.py.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('logical_findings',
    sa.Column('logical_finding_id', sa.String(length=1024), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('account_id', sa.String(length=255), nullable=True),
    sa.Column('resource_id', sa.String(length=1024), nullable=False),
    sa.Column('rule_id', sa.String(length=255), nullable=False),
    sa.Column('state', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=32), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('first_seen_scan_key', sa.String(length=512), nullable=False),
    sa.Column('last_seen_scan_key', sa.String(length=512), nullable=False),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('resolved_scan_key', sa.String(length=512), nullable=True),
    sa.Column('reopen_count', sa.Integer(), nullable=False),
    sa.Column('occurrence_count', sa.Integer(), nullable=False),
    sa.Column('suppressed_reason', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name='ck_logical_findings_severity'),
    sa.CheckConstraint("state <> 'resolved' OR resolved_at IS NOT NULL", name='ck_logical_findings_resolved_has_time'),
    sa.CheckConstraint("state IN ('open', 'resolved', 'reopened', 'suppressed')", name='ck_logical_findings_state'),
    sa.CheckConstraint('last_seen_at >= first_seen_at', name='ck_logical_findings_seen_order'),
    sa.CheckConstraint('occurrence_count >= 1', name='ck_logical_findings_occurrence_positive'),
    sa.CheckConstraint('reopen_count >= 0', name='ck_logical_findings_reopen_non_negative'),
    sa.PrimaryKeyConstraint('logical_finding_id'),
    sa.UniqueConstraint('tenant_id', 'provider', 'account_id', 'resource_id', 'rule_id', name='uq_logical_finding_identity')
    )
    op.create_index('ix_logical_findings_tenant_reopened', 'logical_findings', ['tenant_id', 'reopen_count'], unique=False)
    op.create_index('ix_logical_findings_tenant_resource', 'logical_findings', ['tenant_id', 'resource_id'], unique=False)
    op.create_index('ix_logical_findings_tenant_severity', 'logical_findings', ['tenant_id', 'severity'], unique=False)
    op.create_index('ix_logical_findings_tenant_state', 'logical_findings', ['tenant_id', 'state', 'last_seen_at'], unique=False)
    op.create_table('rule_versions',
    sa.Column('rule_id', sa.String(length=255), nullable=False),
    sa.Column('rule_version', sa.String(length=64), nullable=False),
    sa.Column('title', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('rationale', sa.Text(), nullable=False),
    sa.Column('service', sa.String(length=64), nullable=False),
    sa.Column('domain', sa.String(length=128), nullable=False),
    sa.Column('severity', sa.String(length=32), nullable=False),
    sa.Column('confidence', sa.String(length=32), nullable=False),
    sa.Column('applies_to_resource_type', sa.String(length=128), nullable=True),
    sa.Column('framework', sa.String(length=128), nullable=False),
    sa.Column('control_id', sa.String(length=128), nullable=False),
    sa.Column('remediation', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    sa.Column('framework_mappings', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('references', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('recorded_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name='ck_rule_versions_severity'),
    sa.PrimaryKeyConstraint('rule_id', 'rule_version')
    )
    op.create_index('ix_rule_versions_rule', 'rule_versions', ['rule_id'], unique=False)
    op.create_table('scans',
    sa.Column('scan_key', sa.String(length=512), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('account_id', sa.String(length=255), nullable=True),
    sa.Column('directory_id', sa.String(length=255), nullable=True),
    sa.Column('regions', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('duration_seconds', sa.Float(), nullable=True),
    sa.Column('resource_count', sa.Integer(), nullable=False),
    sa.Column('finding_count', sa.Integer(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('pass_count', sa.Integer(), nullable=False),
    sa.Column('fail_count', sa.Integer(), nullable=False),
    sa.Column('indeterminate_count', sa.Integer(), nullable=False),
    sa.Column('error_count', sa.Integer(), nullable=False),
    sa.Column('scanner_version', sa.String(length=64), nullable=False),
    sa.Column('ruleset_version', sa.String(length=64), nullable=False),
    sa.Column('correlation_id', sa.String(length=255), nullable=True),
    sa.Column('legacy_scan_id', sa.String(length=512), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("(status IN ('completed','partial','failed','cancelled') AND completed_at IS NOT NULL) OR (status IN ('queued','running') AND completed_at IS NULL)", name='ck_scans_terminal_has_completed_at'),
    sa.CheckConstraint("status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')", name='ck_scans_status'),
    sa.CheckConstraint('completed_at IS NULL OR completed_at >= started_at', name='ck_scans_completed_after_started'),
    sa.CheckConstraint('resource_count >= 0 AND finding_count >= 0', name='ck_scans_counts_non_negative'),
    sa.PrimaryKeyConstraint('scan_key')
    )
    op.create_index('ix_scans_tenant_provider_account_started', 'scans', ['tenant_id', 'provider', 'account_id', 'started_at'], unique=False)
    op.create_index('ix_scans_tenant_started', 'scans', ['tenant_id', 'started_at'], unique=False)
    op.create_index('ix_scans_tenant_status', 'scans', ['tenant_id', 'status'], unique=False)
    op.create_table('finding_snapshots',
    sa.Column('finding_id', sa.String(length=1024), nullable=False),
    sa.Column('logical_finding_id', sa.String(length=1024), nullable=True),
    sa.Column('scan_key', sa.String(length=512), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('account_id', sa.String(length=255), nullable=True),
    sa.Column('resource_id', sa.String(length=1024), nullable=False),
    sa.Column('rule_id', sa.String(length=255), nullable=False),
    sa.Column('rule_version', sa.String(length=64), nullable=True),
    sa.Column('framework', sa.String(length=128), nullable=False),
    sa.Column('control_id', sa.String(length=128), nullable=False),
    sa.Column('domain', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('severity', sa.String(length=32), nullable=False),
    sa.Column('evidence', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('region', sa.String(length=64), nullable=True),
    sa.Column('environment', sa.String(length=64), nullable=True),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('superseded_by', sa.String(length=1024), nullable=True),
    sa.Column('risk', sa.Float(), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('related_attack_path_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('related_drift_event_ids', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low')", name='ck_findings_severity'),
    sa.CheckConstraint("status IN ('fail', 'pass', 'indeterminate')", name='ck_findings_status'),
    sa.CheckConstraint('confidence IS NULL OR (confidence >= 0 AND confidence <= 100)', name='ck_findings_confidence_bounded'),
    sa.CheckConstraint('risk IS NULL OR (risk >= 0 AND risk <= 100)', name='ck_findings_risk_bounded'),
    sa.CheckConstraint('superseded_by IS NULL OR superseded_by <> finding_id', name='ck_findings_no_self_supersede'),
    sa.CheckConstraint('version >= 1', name='ck_findings_version_positive'),
    sa.ForeignKeyConstraint(['scan_key'], ['scans.scan_key'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('finding_id')
    )
    op.create_index('ix_findings_tenant_logical', 'finding_snapshots', ['tenant_id', 'logical_finding_id', 'detected_at'], unique=False)
    op.create_index('ix_findings_tenant_resource', 'finding_snapshots', ['tenant_id', 'resource_id'], unique=False)
    op.create_index('ix_findings_tenant_rule', 'finding_snapshots', ['tenant_id', 'rule_id'], unique=False)
    op.create_index('ix_findings_tenant_scan', 'finding_snapshots', ['tenant_id', 'scan_key'], unique=False)
    op.create_index('ix_findings_tenant_scan_severity', 'finding_snapshots', ['tenant_id', 'scan_key', 'severity'], unique=False)
    op.create_index('ix_findings_tenant_scan_status', 'finding_snapshots', ['tenant_id', 'scan_key', 'status'], unique=False)
    op.create_table('resource_snapshots',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('scan_key', sa.String(length=512), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('resource_id', sa.String(length=1024), nullable=False),
    sa.Column('resource_type', sa.String(length=128), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('account_id', sa.String(length=255), nullable=True),
    sa.Column('region', sa.String(length=64), nullable=True),
    sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('attributes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('tags', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('relationships', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.ForeignKeyConstraint(['scan_key'], ['scans.scan_key'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_key', 'resource_id', name='uq_resource_snapshot_scan_resource')
    )
    op.create_index('ix_resource_snapshots_tenant_resource', 'resource_snapshots', ['tenant_id', 'resource_id', 'collected_at'], unique=False)
    op.create_index('ix_resource_snapshots_tenant_scan', 'resource_snapshots', ['tenant_id', 'scan_key'], unique=False)
    op.create_index('ix_resource_snapshots_tenant_type', 'resource_snapshots', ['tenant_id', 'resource_type'], unique=False)
    op.create_table('scan_errors',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('scan_key', sa.String(length=512), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('provider', sa.String(length=32), nullable=False),
    sa.Column('service', sa.String(length=128), nullable=False),
    sa.Column('operation', sa.String(length=128), nullable=False),
    sa.Column('error_code', sa.String(length=128), nullable=False),
    sa.Column('message', sa.Text(), nullable=False),
    sa.Column('retryable', sa.Boolean(), nullable=False),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['scan_key'], ['scans.scan_key'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_errors_tenant_scan', 'scan_errors', ['tenant_id', 'scan_key'], unique=False)


def downgrade() -> None:
    """Drop the whole schema, children before parents.

    A real downgrade, not a `raise NotImplementedError`: this migration
    creates the base schema, so reversing it is unambiguous, and a
    migration you cannot reverse is one you cannot safely rehearse. The
    migration test exercises `downgrade base` followed by a fresh
    `upgrade head` for exactly that reason.

    It is destructive by definition — running it against a database with
    real scan history deletes that history.
    """

    op.drop_index('ix_scan_errors_tenant_scan', table_name='scan_errors')
    op.drop_table('scan_errors')
    op.drop_index('ix_resource_snapshots_tenant_type', table_name='resource_snapshots')
    op.drop_index('ix_resource_snapshots_tenant_scan', table_name='resource_snapshots')
    op.drop_index('ix_resource_snapshots_tenant_resource', table_name='resource_snapshots')
    op.drop_table('resource_snapshots')
    op.drop_index('ix_findings_tenant_scan_status', table_name='finding_snapshots')
    op.drop_index('ix_findings_tenant_scan_severity', table_name='finding_snapshots')
    op.drop_index('ix_findings_tenant_scan', table_name='finding_snapshots')
    op.drop_index('ix_findings_tenant_rule', table_name='finding_snapshots')
    op.drop_index('ix_findings_tenant_resource', table_name='finding_snapshots')
    op.drop_index('ix_findings_tenant_logical', table_name='finding_snapshots')
    op.drop_table('finding_snapshots')
    op.drop_index('ix_scans_tenant_status', table_name='scans')
    op.drop_index('ix_scans_tenant_started', table_name='scans')
    op.drop_index('ix_scans_tenant_provider_account_started', table_name='scans')
    op.drop_table('scans')
    op.drop_index('ix_rule_versions_rule', table_name='rule_versions')
    op.drop_table('rule_versions')
    op.drop_index('ix_logical_findings_tenant_state', table_name='logical_findings')
    op.drop_index('ix_logical_findings_tenant_severity', table_name='logical_findings')
    op.drop_index('ix_logical_findings_tenant_resource', table_name='logical_findings')
    op.drop_index('ix_logical_findings_tenant_reopened', table_name='logical_findings')
    op.drop_table('logical_findings')
