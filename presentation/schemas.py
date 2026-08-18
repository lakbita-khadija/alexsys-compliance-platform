"""Pydantic response/request schemas — the wire contract (Phase 5, §7, §21, §22).

These are the shapes the AI Service and the future dashboard actually
receive, and they are generated into OpenAPI as the published contract.

## The relationship to `contracts/ai_service` (audit conflict C2)

`contracts.ai_service.FindingContract` is frozen at exactly 11 fields and
the AI Service *rejects unknown fields*. It also cannot express an
INDETERMINATE finding at all — its status enum has two values.

The REST API cannot adopt that shape as-is: hiding INDETERMINATE findings
would reintroduce the "hidden compliance" that Phase 3's three-valued
logic exists to prevent, and §7 asks for richer fields the AI contract
forbids.

So there are two schemas, and neither redefines the other:

* ``FindingResource`` — the API view. Three-valued status, plus the
  fields §7 asked about that are *already persisted* (region, scan_key,
  provider, account, lifecycle, first/last seen). This is what
  ``GET /findings`` returns.
* ``AiFindingContract`` — a faithful mirror of the existing 11-field
  contract, produced by the same ``contracts.ai_service.translation``
  ACL that already exists. Requested explicitly via ``?view=ai``.

Both are projections of the same domain ``Finding``. §22's "never
independently redefine the same model differently" is honoured by
deriving both from the domain entity through a single translation path —
not by pretending one shape can serve two incompatible consumers.

The alternative (extending the AI contract) would break the service
another engineer is building right now, and is a v2 decision, not a
Phase 5 one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, Sequence, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from application.ports.queries import DEFAULT_LIMIT, MAX_LIMIT, Page
from domain.audit.models import AuditEvent
from domain.compliance.scoring import ComplianceScore
from domain.findings.models import Finding
from domain.scans.lifecycle import LogicalFinding
from domain.scans.models import Scan

T = TypeVar("T")


class _Schema(BaseModel):
    """Base for every wire schema.

    ``extra="forbid"`` on REQUEST bodies is what makes mass assignment
    impossible: an unknown field is a 422, not a silently-ignored key
    that a future refactor might start honouring.
    """

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------
# Pagination (§6)
# ---------------------------------------------------------------------


class PageMeta(_Schema):
    """The paging envelope, identical across every list endpoint."""

    total: int = Field(description="Total items matching the filter, across all pages.")
    limit: int = Field(description="Page size actually applied.")
    offset: int = Field(description="Zero-based index of the first item returned.")
    has_more: bool = Field(description="Whether further pages exist after this one.")


class PageResponse(_Schema, Generic[T]):
    """``Page[T]`` on the wire.

    Matches §6's contract exactly — ``items``/``total``/``limit``/
    ``offset`` — with ``has_more`` added as a convenience that clients
    would otherwise all compute identically and some would get wrong.
    """

    items: list[T]
    total: int
    limit: int
    offset: int
    has_more: bool

    @classmethod
    def of(cls, page: Page[Any], items: Sequence[T]) -> "PageResponse[T]":
        return cls(
            items=list(items),
            total=page.total,
            limit=page.limit,
            offset=page.offset,
            has_more=page.has_more,
        )


# ---------------------------------------------------------------------
# Errors (§17)
# ---------------------------------------------------------------------


class ErrorDetail(_Schema):
    code: str = Field(description="Stable machine-readable error code. Branch on this.")
    message: str = Field(description="Human-readable explanation. May be reworded; do not parse.")
    correlation_id: str = Field(description="Echoes X-Correlation-ID; quote it in bug reports.")
    details: dict[str, Any] = Field(default_factory=dict)


class ErrorEnvelope(_Schema):
    """The response body of EVERY error this API returns."""

    error: ErrorDetail


# ---------------------------------------------------------------------
# Findings (§7)
# ---------------------------------------------------------------------


class FindingResource(_Schema):
    """A finding as the API exposes it.

    Field ownership, per §7's requirement to justify each one:

    | field | owner | stable | AI | dashboard | persisted | sensitive |
    |---|---|---|---|---|---|---|
    | id | Core | yes | yes | yes | yes | no |
    | tenant_id | Core (JWT) | yes | yes | yes | yes | no |
    | resource_id | Core | yes | yes | yes | yes | no |
    | rule_id | Core | yes | yes | yes | yes | no |
    | framework, control_id, domain | Rule catalog | yes | yes | yes | yes | no |
    | status | Rule engine | yes | 2-valued only | yes | yes | no |
    | severity | Rule catalog | yes | yes | yes | yes | no |
    | evidence | Rule engine | yes | yes | yes | yes | **redacted** |
    | detected_at | Rule engine | yes | yes | yes | yes | no |
    | region, account_id, scan_key | Collector/scan | yes | no | yes | yes | no |
    | logical_finding_id | Core | yes | no | yes | yes | no |
    | risk, confidence | Core (Phase 3) | yes | no | yes | yes | no |
    | related_attack_path_ids | Core (STEP 4) | yes | yes | yes | yes | no |
    | related_resources, indeterminate_resources | Rule engine | yes | yes | yes | yes | no |
    | graph_context | Rule engine | yes | yes | yes | yes | **redacted** |

    ``evidence`` is passed through Phase 4's redaction on the way into
    the database, so what is returned here is already sanitized.
    ``graph_context`` carries edge evidence and is redacted on the same
    path, for the same reason.
    """

    id: str
    tenant_id: str
    resource_id: str
    rule_id: str
    framework: str
    control_id: str
    domain: str
    status: Literal["fail", "pass", "indeterminate"] = Field(
        description=(
            "Three-valued, deliberately. 'indeterminate' means the check could not be "
            "evaluated from the data collected — it is NOT a pass. Clients must not "
            "treat it as one; that is the hidden-compliance failure the rule engine "
            "exists to prevent."
        )
    )
    severity: Literal["critical", "high", "medium", "low"]
    evidence: dict[str, Any] = Field(
        description="Collected facts backing the finding. Secret-shaped keys are redacted."
    )
    detected_at: datetime

    # Additive context — already persisted, exposed because §7 asked and
    # the dashboard needs it. Optional so a finding predating a field is
    # still representable.
    region: str | None = None
    account_id: str | None = None
    scan_key: str | None = None
    logical_finding_id: str | None = Field(
        default=None,
        description="Stable identity of this issue ACROSS scans. Use it for history, not `id`.",
    )
    risk: float | None = None
    confidence: float | None = None

    # Graph and attack-path context (STEP 6). All four were persisted
    # from the moment the columns existed and none of them reached a
    # client — the dashboard could show that a bucket is public but not
    # that it sits at the end of a chain from the internet.
    related_attack_path_ids: list[str] = Field(
        default=[],
        description=(
            "Attack paths this finding's resource lies **on** — referenced by id, "
            "never embedded, because a path carries its whole node and edge list and "
            "copying that into every finding would duplicate the graph per row. "
            "Fetch details from `/api/v1/attack-paths/{id}`.\n\n"
            "**Not the inverse of a path's `contributing_finding_ids`.** This field "
            "answers *is my resource on a path* and is status-agnostic; that one "
            "answers *which misconfigurations create this risk* and lists failures "
            "only. A passing finding on a path resource appears here and not there, "
            "by design — so do not round-trip between the two and expect a fixed point."
        ),
    )
    related_resources: list[str] = Field(
        default=[],
        description=(
            "Neighbouring resources whose state is part of why the rule reached this "
            "conclusion. Populated only for rules that actually traversed the graph."
        ),
    )
    indeterminate_resources: list[str] = Field(
        default=[],
        description=(
            "Neighbours whose contribution could **not** be determined. Kept separate "
            "from `related_resources` so a data gap is never read back as a confirmed "
            "relationship — the same reason `status` is three-valued."
        ),
    )
    graph_context: dict[str, Any] | None = Field(
        default=None,
        description=(
            "The resource's neighbourhood at scan time: incoming and outgoing edges "
            "with their relationship type, confidence and evidence.\n\n"
            "**Returned by the single-finding endpoint only.** A resource's edge count "
            "is unbounded — one security group can front hundreds of instances — so "
            "including it in a 100-item page would make the list response size depend "
            "on graph shape. `null` in a list response means *not requested*, never "
            "*no context*."
        ),
    )

    @classmethod
    def of(
        cls, finding: Finding, *, include_graph_context: bool = False
    ) -> "FindingResource":
        return cls(
            id=str(finding.id),
            tenant_id=str(finding.tenant_id),
            resource_id=str(finding.resource_id),
            rule_id=str(finding.rule_id),
            framework=finding.framework,
            control_id=finding.control_id,
            domain=finding.domain,
            status=finding.status.value,  # type: ignore[arg-type]
            severity=finding.severity.value,  # type: ignore[arg-type]
            evidence=dict(finding.evidence.data),
            detected_at=finding.detected_at,
            region=finding.region,
            account_id=finding.account_id,
            scan_key=finding.scan_id,
            logical_finding_id=finding.logical_finding_id,
            risk=finding.risk,
            confidence=finding.confidence,
            related_attack_path_ids=[str(p) for p in finding.related_attack_path_ids],
            related_resources=list(finding.related_resources),
            indeterminate_resources=list(finding.indeterminate_resources),
            graph_context=(
                dict(finding.graph_context)
                if include_graph_context and finding.graph_context is not None
                else None
            ),
        )


class AiFindingContract(_Schema):
    """The frozen 11-field AI Service contract, on the wire.

    Mirrors ``contracts.ai_service.FindingContract`` exactly — same
    fields, same names, same order. It exists as a Pydantic model only so
    it appears in OpenAPI and the AI engineer can generate a client from
    the published spec; the VALUES always come from the existing
    ``finding_to_contract`` ACL, never from an independent projection
    written here.
    """

    id: str
    tenant_id: str
    resource_id: str
    rule_id: str
    framework: str
    control_id: str
    domain: str
    status: Literal["pass", "fail"] = Field(
        description="Two-valued. INDETERMINATE findings cannot cross this boundary and are omitted."
    )
    severity: Literal["critical", "high", "medium", "low"]
    evidence: dict[str, Any]
    detected_at: datetime


class FindingHistoryItem(_Schema):
    """One appearance of a logical finding in one scan."""

    scan_key: str
    scanned_at: datetime
    status: str
    severity: str
    finding_id: str


class LifecycleResource(_Schema):
    """The cross-scan life of one issue (§25)."""

    logical_finding_id: str
    tenant_id: str
    provider: str
    account_id: str | None
    resource_id: str
    rule_id: str
    state: Literal["open", "resolved", "reopened", "suppressed"]
    severity: str
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    reopen_count: int
    occurrence_count: int

    @classmethod
    def of(cls, lf: LogicalFinding) -> "LifecycleResource":
        return cls(
            logical_finding_id=lf.logical_finding_id,
            tenant_id=str(lf.tenant_id),
            provider=lf.provider.value,
            account_id=lf.account_id,
            resource_id=str(lf.resource_id),
            rule_id=str(lf.rule_id),
            state=lf.state.value,  # type: ignore[arg-type]
            severity=lf.severity.value,
            first_seen_at=lf.first_seen_at,
            last_seen_at=lf.last_seen_at,
            resolved_at=lf.resolved_at,
            reopen_count=lf.reopen_count,
            occurrence_count=lf.occurrence_count,
        )


# ---------------------------------------------------------------------
# Scores (§11)
# ---------------------------------------------------------------------


class ScoreCountsResource(_Schema):
    passed: int
    failed: int
    indeterminate: int
    critical: int
    high: int
    medium: int
    low: int


class ComplianceScoreResource(_Schema):
    """A compliance score.

    ``score`` is nullable and that is load-bearing: ``null`` means
    nothing determinate was evaluated. Clients must render it as "no
    data", never coerce it to 0 or 100 — both are false statements about
    the tenant's posture.

    ``coverage`` is the honesty companion: a 100% score over 4 of 900
    checks is not a good posture, and only ``coverage`` reveals that.
    """

    tenant_id: str
    scope: Literal["tenant", "framework", "domain", "scan"]
    scope_value: str | None
    score: float | None = Field(description="Percent of DETERMINATE checks passed, or null.")
    coverage: float | None = Field(description="Percent of checks that could be determined, or null.")
    counts: ScoreCountsResource
    computed_at: datetime
    scan_key: str | None = None

    @classmethod
    def of(cls, s: ComplianceScore) -> "ComplianceScoreResource":
        return cls(
            tenant_id=str(s.tenant_id),
            scope=s.scope.value,  # type: ignore[arg-type]
            scope_value=s.scope_value,
            score=s.score,
            coverage=s.coverage,
            counts=ScoreCountsResource(
                passed=s.counts.passed,
                failed=s.counts.failed,
                indeterminate=s.counts.indeterminate,
                critical=s.counts.critical,
                high=s.counts.high,
                medium=s.counts.medium,
                low=s.counts.low,
            ),
            computed_at=s.computed_at,
            scan_key=s.scan_key,
        )


# ---------------------------------------------------------------------
# Scans (§26)
# ---------------------------------------------------------------------


class ScanRequest(_Schema):
    """``POST /api/v1/scans`` body.

    No ``tenant_id``: it comes from the verified token. Accepting one
    here would create exactly the "trust the client's tenant" hole §12
    forbids, and ``extra="forbid"`` means sending one is a 422 rather
    than a silently ignored field.
    """

    provider: Literal["aws", "azure"] = Field(
        description="Cloud provider to scan. GCP is not implemented; see docs/architecture/phase-5-audit.md."
    )
    account_id: str | None = Field(
        default=None, description="AWS account id or Azure subscription id."
    )
    directory_id: str | None = Field(
        default=None, description="Azure tenant (directory) id, where applicable."
    )
    regions: list[str] = Field(default_factory=list)


class ScanSubmissionResponse(_Schema):
    """``202 Accepted``. An id and a status — never results.

    A submission response containing findings would imply the scan had
    finished, which is the misconception §26 asks the contract to avoid.
    Poll ``GET /api/v1/scans/{scan_key}`` for progress.
    """

    scan_key: str
    status: Literal["queued", "running", "completed", "partial", "failed", "cancelled"]
    tenant_id: str
    submitted_at: datetime


class ScanErrorResource(_Schema):
    provider: str
    service: str
    operation: str
    error_code: str
    message: str
    retryable: bool
    occurred_at: datetime


class ScanResource(_Schema):
    """A scan's full state.

    ``partial`` is a first-class status, not a variant of ``completed``:
    a scan that enumerated S3 but was denied KMS has NOT verified KMS,
    and reporting it as completed would tell an auditor that KMS was
    checked and found compliant. Consult ``errors`` whenever status is
    ``partial``.
    """

    scan_key: str
    tenant_id: str
    provider: str
    account_id: str | None
    directory_id: str | None
    regions: list[str]
    status: Literal["queued", "running", "completed", "partial", "failed", "cancelled"]
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None
    resource_count: int
    finding_count: int
    pass_count: int
    fail_count: int
    indeterminate_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_count: int
    errors: list[ScanErrorResource] = Field(default_factory=list)

    @classmethod
    def of(cls, scan: Scan) -> "ScanResource":
        c = scan.counts
        return cls(
            scan_key=scan.scan_key,
            tenant_id=str(scan.tenant_id),
            provider=scan.target.provider.value,
            account_id=scan.target.account_id,
            directory_id=scan.target.directory_id,
            regions=list(scan.target.regions),
            status=scan.status.value,  # type: ignore[arg-type]
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            duration_seconds=scan.duration_seconds,
            resource_count=c.resource_count,
            finding_count=c.finding_count,
            pass_count=c.pass_count,
            fail_count=c.fail_count,
            indeterminate_count=c.indeterminate_count,
            critical_count=c.critical_count,
            high_count=c.high_count,
            medium_count=c.medium_count,
            low_count=c.low_count,
            error_count=c.error_count,
            errors=[
                ScanErrorResource(
                    provider=e.provider.value,
                    service=e.service,
                    operation=e.operation,
                    error_code=e.error_code,
                    message=e.message,
                    retryable=e.retryable,
                    occurred_at=e.occurred_at,
                )
                for e in scan.errors
            ],
        )


# ---------------------------------------------------------------------
# Audit (§27)
# ---------------------------------------------------------------------


class AuditEventResource(_Schema):
    event_id: str
    tenant_id: str
    actor_subject: str
    actor_kind: str
    action: str
    resource: str | None
    resource_type: str | None
    occurred_at: datetime
    correlation_id: str | None
    metadata: dict[str, Any]

    @classmethod
    def of(cls, e: AuditEvent) -> "AuditEventResource":
        return cls(
            event_id=e.event_id,
            tenant_id=str(e.tenant_id),
            actor_subject=e.actor.subject,
            actor_kind=e.actor.kind,
            action=e.action.value,
            resource=e.resource,
            resource_type=e.resource_type,
            occurred_at=e.occurred_at,
            correlation_id=e.correlation_id,
            metadata=dict(e.metadata),
        )


# ---------------------------------------------------------------------
# Auth / meta
# ---------------------------------------------------------------------


class TokenRequestBody(_Schema):
    """Client-credentials token request (§13).

    Audit conflict C4: §13 requires Core to issue tokens, but no user
    store exists and §36 never asks for one. This is the
    service-to-service reading — credentials identify a configured
    *client* (the AI Service, the dashboard), not a human. No password
    hashing, no user table, no login flow is invented.
    """

    client_id: str
    client_secret: str = Field(description="Never logged, never echoed, never persisted in plaintext.")


class TokenResponse(_Schema):
    access_token: str
    token_type: Literal["Bearer"]
    expires_in: int
    expires_at: datetime


class HealthResponse(_Schema):
    status: Literal["ok", "degraded"]
    database: Literal["ok", "unavailable"]


class VersionResponse(_Schema):
    service: str
    version: str
    api_version: str


__all__ = [
    "AiFindingContract",
    "AuditEventResource",
    "ComplianceScoreResource",
    "DEFAULT_LIMIT",
    "ErrorEnvelope",
    "ErrorDetail",
    "FindingHistoryItem",
    "FindingResource",
    "HealthResponse",
    "LifecycleResource",
    "MAX_LIMIT",
    "PageMeta",
    "PageResponse",
    "ScanRequest",
    "ScanResource",
    "ScanSubmissionResponse",
    "ScoreCountsResource",
    "TokenRequestBody",
    "TokenResponse",
    "VersionResponse",
]


class AttackPathNode(_Schema):
    """One hop in an attack path."""

    resource_id: str
    resource_type: str
    provider: str | None = None
    account_id: str | None = None
    region: str | None = None
    confidence: str
    kind: str


class AttackPathEdge(_Schema):
    """One relationship traversed."""

    source: str
    target: str
    relationship: str
    blocked: bool = False
    confidence: str
    evidence: dict = {}


class AttackPathResource(_Schema):
    """An attack path as the API exposes it (STEP 5).

    Carries the full chain and its scoring breakdown, because the number
    is only useful if it can be defended. ``evidence.score_factors``
    names every contribution and penalty that produced ``risk_score``.

    ``nodes`` and ``edges`` are ORDERED — a path whose hops reorder is a
    different path, and the UI renders them as a sequence.
    """

    id: str
    tenant_id: str
    scan_key: str
    scenario: str
    provider: str | None = None
    severity: str
    risk_score: float
    confidence: str
    source: str
    target: str
    nodes: list[AttackPathNode] = []
    edges: list[AttackPathEdge] = []
    evidence: dict = {}
    contributing_finding_ids: list[str] = []
    algorithm_version: str
    scoring_model_version: str | None = None
    #: Topology hash excluding score and provenance, so "is this the same
    #: path as last week" survives a re-scoring.
    fingerprint: str
    created_at: datetime

    @classmethod
    def of(cls, row: dict) -> "AttackPathResource":
        return cls(
            id=row["id"],
            tenant_id=row["tenant_id"],
            scan_key=row["scan_key"],
            scenario=row["scenario"],
            provider=row.get("provider"),
            severity=row["severity"],
            risk_score=row["risk_score"],
            confidence=row["confidence"],
            source=row["source"],
            target=row["target"],
            nodes=[AttackPathNode(**n) for n in row.get("nodes", [])],
            edges=[AttackPathEdge(**e) for e in row.get("edges", [])],
            evidence=dict(row.get("evidence", {})),
            contributing_finding_ids=list(row.get("contributing_finding_ids", [])),
            algorithm_version=row["algorithm_version"],
            scoring_model_version=row.get("scoring_model_version"),
            fingerprint=row["fingerprint"],
            created_at=row["created_at"],
        )


class AttackPathSummary(_Schema):
    """Counts by severity — the dashboard's landing view (§20)."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0

    @classmethod
    def of(cls, rows) -> "AttackPathSummary":
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in rows:
            if row["severity"] in counts:
                counts[row["severity"]] += 1
        return cls(**counts, total=len(rows))


class AttackPathListResponse(_Schema):
    """Paths plus their severity summary, in one round trip.

    The dashboard needs both to render its landing screen, and two
    endpoints would guarantee they eventually disagree.
    """

    summary: AttackPathSummary
    items: list[AttackPathResource] = []
