"""Finding graph contextualization (graph expansion §3).

Revision ID: 0003
Revises: 0002

Adds three columns to ``finding_snapshots`` so a cross-resource finding
can name the resources it matched:

* ``related_resources`` — the neighbours whose state is part of why the
  rule reached its conclusion.
* ``indeterminate_resources`` — neighbours whose contribution could not
  be determined, kept in a separate column so a data gap is never read
  back as a confirmed relationship.
* ``graph_context`` — the subject's neighbourhood, present only when the
  rule actually traversed the graph.

**Why these are stored rather than derived on read.** The resource graph
is rebuilt per scan and never persisted, so a finding fetched tomorrow
cannot recompute which security group it matched — the graph that knew is
gone. Context that lives only in the process that produced the finding is
the same as no context at all.

Purely additive. The two array columns are NOT NULL with a server default
of ``'[]'`` so existing rows backfill to "related to nothing", which is
the truthful value for every finding written before traversal was
recorded — none of them examined a neighbour. ``graph_context`` is
nullable for the same reason: NULL means "no traversal recorded", which
is exactly the historical state.

The server defaults are kept (not dropped after backfill) because the
application is not the only writer during a rolling deploy: an older
process still running the previous release inserts rows without these
columns, and without a default that insert fails.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "finding_snapshots",
        sa.Column(
            "related_resources",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "finding_snapshots",
        sa.Column(
            "indeterminate_resources",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "finding_snapshots",
        sa.Column(
            "graph_context",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("finding_snapshots", "graph_context")
    op.drop_column("finding_snapshots", "indeterminate_resources")
    op.drop_column("finding_snapshots", "related_resources")
