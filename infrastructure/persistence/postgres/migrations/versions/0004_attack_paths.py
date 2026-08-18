"""Attack path persistence (STEP 4).

Revision ID: 0004
Revises: 0003

Adds the ``attack_paths`` table.

**Why paths are stored rather than recomputed.** The ResourceGraph is
rebuilt every scan and never persisted, so a path fetched tomorrow cannot
be rediscovered — the graph that found it is gone. Before this migration
`ScanCloudAccount` produced attack paths and `PersistScanResult` silently
dropped them; only their *risk* survived, via
`Finding.related_attack_path_ids`.

**Why nodes and edges are JSONB rather than child tables.** A path is
read as one unit — a partial path is meaningless — is never queried
independently, and is never joined against. Two child tables would buy
normalization nobody uses and cost a join on every read. The identifiers
inside stay reachable through JSONB operators if that changes.

**Composite primary key** ``(attack_path_id, scan_key)``: the path id is
a deterministic composite, so the *same* path recurs across scans by
design. Keying on the id alone would make each scan overwrite the last
and destroy history.

Purely additive — no existing table, column, constraint or index is
touched.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "attack_paths",
        sa.Column("attack_path_id", sa.String(length=1024), nullable=False),
        sa.Column("scan_key", sa.String(length=512), nullable=False),
        sa.Column("tenant_id", sa.String(length=255), nullable=False),
        sa.Column("scenario", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=1024), nullable=False),
        sa.Column("target_id", sa.String(length=1024), nullable=False),
        sa.Column("nodes", _JSONB, nullable=False),
        sa.Column("edges", _JSONB, nullable=False),
        sa.Column("evidence", _JSONB, nullable=False),
        sa.Column("contributing_finding_ids", _JSONB, nullable=False),
        sa.Column("algorithm_version", sa.String(length=64), nullable=False),
        sa.Column("scoring_model_version", sa.String(length=64), nullable=True),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_key"], ["scans.scan_key"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("attack_path_id", "scan_key"),
        # Mirrors the domain invariants, so a manual UPDATE cannot
        # corrupt what the aggregate would reject.
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low')",
            name="ck_attack_paths_severity",
        ),
        sa.CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="ck_attack_paths_risk_bounded"
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low', 'unknown')",
            name="ck_attack_paths_confidence",
        ),
    )
    op.create_index(
        "ix_attack_paths_tenant_scan", "attack_paths", ["tenant_id", "scan_key"]
    )
    op.create_index(
        "ix_attack_paths_tenant_severity", "attack_paths", ["tenant_id", "severity"]
    )
    op.create_index(
        "ix_attack_paths_tenant_scenario", "attack_paths", ["tenant_id", "scenario"]
    )
    op.create_index(
        "ix_attack_paths_tenant_target", "attack_paths", ["tenant_id", "target_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_attack_paths_tenant_target", table_name="attack_paths")
    op.drop_index("ix_attack_paths_tenant_scenario", table_name="attack_paths")
    op.drop_index("ix_attack_paths_tenant_severity", table_name="attack_paths")
    op.drop_index("ix_attack_paths_tenant_scan", table_name="attack_paths")
    op.drop_table("attack_paths")
