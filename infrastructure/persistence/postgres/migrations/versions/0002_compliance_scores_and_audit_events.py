"""Compliance scores and audit events (Phase 5).

Revision ID: 0002
Revises: 0001

Adds the two tables Phase 5 introduces:

* ``compliance_scores`` — computed, immutable posture numbers. The unique
  index uses ``NULLS NOT DISTINCT`` so the tenant-scope row (whose
  ``scope_value`` is NULL by definition) participates in it; with default
  NULL semantics every recompute would insert a duplicate instead of
  replacing.
* ``audit_events`` — append-only security trail.

Purely additive: no existing table, column, constraint or index is
touched, so Phases 1-4 are unaffected and this migration can be applied
to a database already carrying scan history.

Generated with ``alembic revision --autogenerate`` and reviewed against
infrastructure/persistence/postgres/models/tables.py.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('audit_events',
    sa.Column('event_id', sa.String(length=128), nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('actor_subject', sa.String(length=255), nullable=False),
    sa.Column('actor_kind', sa.String(length=16), nullable=False),
    sa.Column('action', sa.String(length=64), nullable=False),
    sa.Column('resource', sa.String(length=1024), nullable=True),
    sa.Column('resource_type', sa.String(length=64), nullable=True),
    sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('correlation_id', sa.String(length=128), nullable=True),
    sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.CheckConstraint("actor_kind IN ('client', 'system')", name='ck_audit_actor_kind'),
    sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index('ix_audit_tenant_action', 'audit_events', ['tenant_id', 'action'], unique=False)
    op.create_index('ix_audit_tenant_correlation', 'audit_events', ['tenant_id', 'correlation_id'], unique=False)
    op.create_index('ix_audit_tenant_time', 'audit_events', ['tenant_id', 'occurred_at'], unique=False)
    op.create_table('compliance_scores',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=255), nullable=False),
    sa.Column('scope', sa.String(length=32), nullable=False),
    sa.Column('scope_value', sa.String(length=255), nullable=True),
    sa.Column('scan_key', sa.String(length=512), nullable=True),
    sa.Column('passed', sa.Integer(), nullable=False),
    sa.Column('failed', sa.Integer(), nullable=False),
    sa.Column('indeterminate', sa.Integer(), nullable=False),
    sa.Column('critical', sa.Integer(), nullable=False),
    sa.Column('high', sa.Integer(), nullable=False),
    sa.Column('medium', sa.Integer(), nullable=False),
    sa.Column('low', sa.Integer(), nullable=False),
    sa.Column('computed_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("(scope = 'tenant' AND scope_value IS NULL) OR (scope <> 'tenant' AND scope_value IS NOT NULL)", name='ck_scores_scope_value_presence'),
    sa.CheckConstraint("scope IN ('tenant', 'framework', 'domain', 'scan')", name='ck_scores_scope'),
    sa.CheckConstraint('passed >= 0 AND failed >= 0 AND indeterminate >= 0', name='ck_scores_counts_non_negative'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scores_tenant_computed', 'compliance_scores', ['tenant_id', 'computed_at'], unique=False)
    op.create_index('ix_scores_tenant_scope_time', 'compliance_scores', ['tenant_id', 'scope', 'scope_value', 'computed_at'], unique=False)
    op.create_index('uq_score_identity', 'compliance_scores', ['tenant_id', 'scope', 'scope_value', 'scan_key'], unique=True, postgresql_nulls_not_distinct=True)


def downgrade() -> None:
    """Drop both tables. Destructive: discards computed scores and the
    audit trail. Reversible in the schema sense, not the data sense.
    """

    op.drop_index('uq_score_identity', table_name='compliance_scores', postgresql_nulls_not_distinct=True)
    op.drop_index('ix_scores_tenant_scope_time', table_name='compliance_scores')
    op.drop_index('ix_scores_tenant_computed', table_name='compliance_scores')
    op.drop_table('compliance_scores')
    op.drop_index('ix_audit_tenant_time', table_name='audit_events')
    op.drop_index('ix_audit_tenant_correlation', table_name='audit_events')
    op.drop_index('ix_audit_tenant_action', table_name='audit_events')
    op.drop_table('audit_events')
