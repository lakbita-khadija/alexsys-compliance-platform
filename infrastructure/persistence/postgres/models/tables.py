"""SQLAlchemy 2.x ORM models (Phase 4, Parts 10 & 12).

These are PERSISTENCE models, not domain models. ``PostgresScanModel`` is
not ``domain.scans.models.Scan`` and must never be returned from a
repository — explicit mappers in ``../mappers/`` translate between them.
The domain models are frozen dataclasses with validating constructors;
an ORM instance could not satisfy those invariants even if we wanted it
to, which is a useful structural guarantee rather than a nuisance.

Schema design notes:

* **JSONB, not JSON** — JSONB is binary, supports GIN indexing, and
  deduplicates keys. JSON's only advantage (preserving key order and
  whitespace) is irrelevant here.
* **Normalized columns for anything queried; JSONB for provider-specific
  state.** Part 5 warns against putting everything in JSONB, and the
  reason is concrete: you cannot efficiently index or constrain what you
  cannot see. Everything a dashboard filters or groups by is a real
  column; the open-ended cloud state is JSONB.
* **`tenant_id` on every table**, always first in composite indexes.
  It is the isolation root, and leading a composite index with it means
  every tenant-scoped query is index-served (Part 18).
* **`TIMESTAMP(timezone=True)` everywhere.** The domain enforces
  tz-aware datetimes; naive columns would silently drop that guarantee.
* **Enums stored as `TEXT` + CHECK constraint**, not PostgreSQL native
  ENUM types. Native enums require `ALTER TYPE` to add a value, which
  takes a lock and cannot run inside a transaction in older versions —
  a needless migration hazard for a vocabulary (`CloudProvider`) that is
  explicitly expected to grow.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Declarative base for every ComplianceIQ persistence model."""


# The closed vocabularies, mirrored as CHECK constraints so the database
# rejects a value the application would consider impossible. Defense in
# depth: the domain validates on the way in, the database validates at
# rest, and a bug or a manual UPDATE cannot corrupt the enum.
_SCAN_STATUSES = ("queued", "running", "completed", "partial", "failed", "cancelled")
_FINDING_STATUSES = ("fail", "pass", "indeterminate")
_SEVERITIES = ("critical", "high", "medium", "low")
_LIFECYCLE_STATES = ("open", "resolved", "reopened", "suppressed")


def _in_check(column: str, values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({rendered})"


class PostgresScanModel(Base):
    """One scan execution. The root of every other table here."""

    __tablename__ = "scans"

    scan_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # --- ScanTarget, flattened. Provider-agnostic by design (Part 4):
    # `account_id` holds an AWS account id OR an Azure subscription id OR
    # a future GCP project id. Adding a provider needs no schema change.
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    directory_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    regions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    status: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    # --- Denormalized summary (ScanCounts). Stored, not computed: see
    # domain/scans/models.py:ScanCounts for why.
    resource_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pass_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indeterminate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    scanner_version: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    correlation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    legacy_scan_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_in_check("status", _SCAN_STATUSES), name="ck_scans_status"),
        CheckConstraint("resource_count >= 0 AND finding_count >= 0", name="ck_scans_counts_non_negative"),
        CheckConstraint(
            "completed_at IS NULL OR completed_at >= started_at", name="ck_scans_completed_after_started"
        ),
        # Terminal states must carry a completion time; non-terminal must
        # not. The same invariant the Scan aggregate enforces, mirrored
        # here so it survives any write path.
        CheckConstraint(
            "(status IN ('completed','partial','failed','cancelled') AND completed_at IS NOT NULL)"
            " OR (status IN ('queued','running') AND completed_at IS NULL)",
            name="ck_scans_terminal_has_completed_at",
        ),
        # "Recent scans for this tenant" — the single most common query
        # (GET /scans, dashboard landing page). DESC matches the sort.
        Index("ix_scans_tenant_started", "tenant_id", "started_at"),
        Index("ix_scans_tenant_status", "tenant_id", "status"),
        # Compliance history is always filtered by target then time.
        Index("ix_scans_tenant_provider_account_started", "tenant_id", "provider", "account_id", "started_at"),
    )


class PostgresScanErrorModel(Base):
    """A structured partial failure (Part 19).

    NEVER carries a credential: `message` is sanitized before it reaches
    here, and `infrastructure/persistence/postgres/mappers/redaction.py`
    is the enforcing guard.
    """

    __tablename__ = "scan_errors"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_key: Mapped[str] = mapped_column(
        String(512), ForeignKey("scans.scan_key", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    service: Mapped[str] = mapped_column(String(128), nullable=False)
    operation: Mapped[str] = mapped_column(String(128), nullable=False)
    error_code: Mapped[str] = mapped_column(String(128), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("ix_scan_errors_tenant_scan", "tenant_id", "scan_key"),)


class PostgresResourceSnapshotModel(Base):
    """What a resource looked like during one scan (Part 5)."""

    __tablename__ = "resource_snapshots"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_key: Mapped[str] = mapped_column(
        String(512), ForeignKey("scans.scan_key", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)

    # --- Structured/indexed: everything a query filters or groups by.
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # --- Flexible: provider-specific state nobody can enumerate up front.
    attributes: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    tags: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    relationships: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        # One snapshot per resource per scan. Makes re-persisting a scan
        # idempotent instead of duplicating rows.
        UniqueConstraint("scan_key", "resource_id", name="uq_resource_snapshot_scan_resource"),
        Index("ix_resource_snapshots_tenant_scan", "tenant_id", "scan_key"),
        # "How did this resource change over time?" — resource history.
        Index("ix_resource_snapshots_tenant_resource", "tenant_id", "resource_id", "collected_at"),
        Index("ix_resource_snapshots_tenant_type", "tenant_id", "resource_type"),
    )


class PostgresFindingSnapshotModel(Base):
    """One finding as observed in one scan (Part 6).

    Preserves the full Phase 3 ``Finding`` contract. Rule METADATA
    (title, description, rationale, remediation, framework_mappings)
    lives in ``rule_versions`` and is joined — see that model for why.
    """

    __tablename__ = "finding_snapshots"

    finding_id: Mapped[str] = mapped_column(String(1024), primary_key=True)
    logical_finding_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    scan_key: Mapped[str] = mapped_column(
        String(512), ForeignKey("scans.scan_key", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)

    account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    framework: Mapped[str] = mapped_column(String(128), nullable=False)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    domain: Mapped[str] = mapped_column(String(128), nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[str | None] = mapped_column(String(64), nullable=True)

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    superseded_by: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    risk: Mapped[float | None] = mapped_column(Float, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    related_attack_path_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    related_drift_event_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    # Graph contextualization (expansion §3). Stored rather than derived
    # on read: the graph is rebuilt per scan and never persisted, so a
    # finding read back tomorrow cannot recompute which security group it
    # matched. Without these columns the context would exist only in the
    # process that produced the finding — which is the same as not
    # existing.
    #
    # These two carry a SERVER default as well as a Python one, unlike
    # the older JSONB list columns above. Two reasons, both about the
    # column being added to a table that already has rows: a NOT NULL
    # column cannot be added to a populated table without one, and during
    # a rolling deploy an older process still running the previous
    # release inserts rows that do not mention these columns at all.
    # Declared here as well as in migration 0003 so the schema-parity
    # test can see that the model and the database agree.
    related_resources: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    indeterminate_resources: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    graph_context: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        CheckConstraint(_in_check("status", _FINDING_STATUSES), name="ck_findings_status"),
        CheckConstraint(_in_check("severity", _SEVERITIES), name="ck_findings_severity"),
        CheckConstraint(
            "risk IS NULL OR (risk >= 0 AND risk <= 100)", name="ck_findings_risk_bounded"
        ),
        CheckConstraint(
            "confidence IS NULL OR (confidence >= 0 AND confidence <= 100)",
            name="ck_findings_confidence_bounded",
        ),
        CheckConstraint("version >= 1", name="ck_findings_version_positive"),
        # A finding cannot supersede itself — mirrors the domain rule.
        CheckConstraint(
            "superseded_by IS NULL OR superseded_by <> finding_id", name="ck_findings_no_self_supersede"
        ),
        # GET /scans/{id}/findings, with the status/severity filters a
        # dashboard always applies.
        Index("ix_findings_tenant_scan", "tenant_id", "scan_key"),
        Index("ix_findings_tenant_scan_status", "tenant_id", "scan_key", "status"),
        Index("ix_findings_tenant_scan_severity", "tenant_id", "scan_key", "severity"),
        # GET /findings/{logical_finding_id}/history.
        Index("ix_findings_tenant_logical", "tenant_id", "logical_finding_id", "detected_at"),
        # "Everything wrong with this resource" / "everywhere this rule fires".
        Index("ix_findings_tenant_resource", "tenant_id", "resource_id"),
        Index("ix_findings_tenant_rule", "tenant_id", "rule_id"),
    )


class PostgresLogicalFindingModel(Base):
    """The cross-scan lifecycle of one security issue (Part 7).

    The identity COMPONENTS are separate columns, and the uniqueness
    constraint is on those — not on ``logical_finding_id``. That string
    embeds ``:``, which also appears inside ARNs, making it unparseable
    (audit §3); constraining the components keeps identity meaningful
    even though the string is opaque.
    """

    __tablename__ = "logical_findings"

    logical_finding_id: Mapped[str] = mapped_column(String(1024), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)

    state: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen_scan_key: Mapped[str] = mapped_column(String(512), nullable=False)
    last_seen_scan_key: Mapped[str] = mapped_column(String(512), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_scan_key: Mapped[str | None] = mapped_column(String(512), nullable=True)

    reopen_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    suppressed_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_in_check("state", _LIFECYCLE_STATES), name="ck_logical_findings_state"),
        CheckConstraint(_in_check("severity", _SEVERITIES), name="ck_logical_findings_severity"),
        CheckConstraint("last_seen_at >= first_seen_at", name="ck_logical_findings_seen_order"),
        CheckConstraint("reopen_count >= 0", name="ck_logical_findings_reopen_non_negative"),
        CheckConstraint("occurrence_count >= 1", name="ck_logical_findings_occurrence_positive"),
        CheckConstraint(
            "state <> 'resolved' OR resolved_at IS NOT NULL", name="ck_logical_findings_resolved_has_time"
        ),
        # THE cross-account safety constraint: two accounts with the same
        # resource id and rule are two DIFFERENT issues.
        UniqueConstraint(
            "tenant_id",
            "provider",
            "account_id",
            "resource_id",
            "rule_id",
            name="uq_logical_finding_identity",
        ),
        # "What is wrong right now?" — the active-findings query.
        Index("ix_logical_findings_tenant_state", "tenant_id", "state", "last_seen_at"),
        Index("ix_logical_findings_tenant_severity", "tenant_id", "severity"),
        # "Which rule regressed?"
        Index("ix_logical_findings_tenant_reopened", "tenant_id", "reopen_count"),
        Index("ix_logical_findings_tenant_resource", "tenant_id", "resource_id"),
    )


class PostgresRuleVersionModel(Base):
    """Rule metadata, stored once per ``(rule_id, rule_version)``.

    Part 6 asks that title/description/rationale/remediation/
    framework_mappings be preserved. They live HERE rather than on every
    finding row because they are rule-scoped, not finding-scoped:
    denormalising a ~2 KB remediation block onto every finding would
    multiply it by resources × scans, for data that is identical across
    all of them. A join costs one indexed lookup; the duplication would
    cost gigabytes and make a rule-text correction require rewriting
    history.

    Documented as a deliberate deviation from a literal reading of
    Part 6 — no information is lost, only stored once.
    """

    __tablename__ = "rule_versions"

    rule_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    rule_version: Mapped[str] = mapped_column(String(64), primary_key=True)

    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    service: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    domain: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False, default="high")
    applies_to_resource_type: Mapped[str | None] = mapped_column(String(128), nullable=True)

    framework: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    control_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")

    remediation: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    framework_mappings: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False, default=list)
    references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_in_check("severity", _SEVERITIES), name="ck_rule_versions_severity"),
        Index("ix_rule_versions_rule", "rule_id"),
    )


class PostgresComplianceScoreModel(Base):
    """A computed compliance score (Phase 5, §11).

    Immutable once written: a score describes what was true at
    ``computed_at``, and recomputing history would make last quarter's
    number silently change. Re-running the SAME scan's scoring replaces
    the row by identity (idempotent retry); a new scan writes new rows.

    The counts are stored alongside the percentage because a bare "73.5%"
    is unfalsifiable. "203 passed, 73 failed, 12 could not be evaluated"
    can be checked against the findings themselves, which is what makes
    the number auditable.
    """

    __tablename__ = "compliance_scores"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    #: NULL only for tenant scope, whose value is the tenant itself.
    scope_value: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scan_key: Mapped[str | None] = mapped_column(String(512), nullable=True)

    passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indeterminate: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            _in_check("scope", ("tenant", "framework", "domain", "scan")),
            name="ck_scores_scope",
        ),
        CheckConstraint(
            "passed >= 0 AND failed >= 0 AND indeterminate >= 0",
            name="ck_scores_counts_non_negative",
        ),
        # Mirrors the domain invariant: only TENANT scope may omit a
        # scope_value. A framework score that does not say which
        # framework is a number, not a score.
        CheckConstraint(
            "(scope = 'tenant' AND scope_value IS NULL)"
            " OR (scope <> 'tenant' AND scope_value IS NOT NULL)",
            name="ck_scores_scope_value_presence",
        ),
        # Recomputing one scan's scores must replace, not duplicate.
        # NULLS NOT DISTINCT so the tenant-scope row (scope_value NULL)
        # participates: with default NULL semantics every recompute
        # would insert another row.
        Index(
            "uq_score_identity",
            "tenant_id",
            "scope",
            "scope_value",
            "scan_key",
            unique=True,
            postgresql_nulls_not_distinct=True,
        ),
        # The trend query: one scope's score over time.
        Index("ix_scores_tenant_scope_time", "tenant_id", "scope", "scope_value", "computed_at"),
        Index("ix_scores_tenant_computed", "tenant_id", "computed_at"),
    )


class PostgresAuditEventModel(Base):
    """One immutable audit record (Phase 5, §27).

    Append-only by design and by repository contract: no UPDATE and no
    DELETE path exists. An audit trail that can be edited is not
    evidence.
    """

    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_kind: Mapped[str] = mapped_column(String(16), nullable=False, default="client")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Free-form context. The domain rejects credential-shaped keys, and
    #: the mapper redacts again on the way in (defense in depth).
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    __table_args__ = (
        CheckConstraint(
            _in_check("actor_kind", ("client", "system")), name="ck_audit_actor_kind"
        ),
        Index("ix_audit_tenant_time", "tenant_id", "occurred_at"),
        Index("ix_audit_tenant_action", "tenant_id", "action"),
        # "What happened during request X?" — the correlation-id trace.
        Index("ix_audit_tenant_correlation", "tenant_id", "correlation_id"),
    )


class PostgresAttackPathModel(Base):
    """A discovered attack path (STEP 4).

    Stored rather than recomputed, for the same reason finding graph
    context is: the ResourceGraph is rebuilt per scan and never
    persisted, so a path fetched tomorrow cannot be rediscovered — the
    graph that found it is gone.

    Nodes and edges are JSONB rather than child tables. They are read as
    one unit (a path is meaningless partially), never queried
    independently, and never joined against — so two extra tables would
    buy normalization nobody uses and cost a join on every read. The
    identifiers inside remain queryable via JSONB operators if that ever
    changes.
    """

    __tablename__ = "attack_paths"

    #: Deterministic composite: tenant:scenario:entry:target. The same
    #: path in two scans of unchanged infrastructure gets the same id,
    #: which is what makes it trackable over time.
    attack_path_id: Mapped[str] = mapped_column(String(1024), primary_key=True)
    scan_key: Mapped[str] = mapped_column(
        String(512), ForeignKey("scans.scan_key", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)

    scenario: Mapped[str] = mapped_column(String(128), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(32), nullable=True)

    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)

    source_id: Mapped[str] = mapped_column(String(1024), nullable=False)
    target_id: Mapped[str] = mapped_column(String(1024), nullable=False)

    #: Ordered. A path whose hops reorder is a different path.
    nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    contributing_finding_ids: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list
    )

    algorithm_version: Mapped[str] = mapped_column(String(64), nullable=False)
    scoring_model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Topology hash excluding provenance and score, so "is this the same
    #: path as last week" survives a re-scoring.
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_in_check("severity", _SEVERITIES), name="ck_attack_paths_severity"),
        CheckConstraint(
            "risk_score >= 0 AND risk_score <= 100", name="ck_attack_paths_risk_bounded"
        ),
        CheckConstraint(
            _in_check("confidence", ("high", "medium", "low", "unknown")),
            name="ck_attack_paths_confidence",
        ),
        # GET /scans/{id}/attack-paths, ranked.
        Index("ix_attack_paths_tenant_scan", "tenant_id", "scan_key"),
        Index("ix_attack_paths_tenant_severity", "tenant_id", "severity"),
        Index("ix_attack_paths_tenant_scenario", "tenant_id", "scenario"),
        # "everything implicating this resource"
        Index("ix_attack_paths_tenant_target", "tenant_id", "target_id"),
    )
