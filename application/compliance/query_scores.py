"""Compliance score use cases (Phase 5, §11).

Two responsibilities, deliberately separated:

* ``ComputeScoresForScan`` — writes. Runs at the end of a scan, turning
  that scan's findings into stored ``ComplianceScore`` rows.
* ``QueryScores`` / ``GetLatestScore`` — reads. Serve the API.

They are separate because scoring at *read* time would be the obvious
and wrong design. A dashboard asking "what is our ISO 27001 score?"
would re-aggregate every finding in the tenant on every page load, and
worse, the number would drift as history was appended — last quarter's
score would silently change. Scores are computed once, when the scan
that produced them completes, and are immutable thereafter.
"""

from __future__ import annotations

from datetime import datetime

from application.ports.auth import AuthenticatedIdentity, Role
from application.ports.queries import (
    ComplianceScoreRepository,
    Page,
    PageRequest,
    ScoreFilter,
)
from domain.compliance.scoring import (
    ComplianceScore,
    ScoreScope,
    score_for_scope,
    scores_by_dimension,
)
from domain.findings.models import Finding
from domain.shared.identifiers import TenantId


class ComputeScoresForScan:
    """Derive and persist every score a completed scan produces.

    One scan yields several scores: one for the scan overall, one per
    framework it touched, and one per risk domain. All are computed from
    the same finding set in a single pass, at the same ``computed_at``,
    so they are mutually consistent — a framework score and the scan
    score can never disagree about what was evaluated.
    """

    def __init__(self, repository: ComplianceScoreRepository) -> None:
        self._repository = repository

    def execute(
        self,
        *,
        tenant_id: TenantId,
        scan_key: str,
        findings: tuple[Finding, ...],
        computed_at: datetime,
    ) -> tuple[ComplianceScore, ...]:
        scan_score = score_for_scope(
            tenant_id=tenant_id,
            scope=ScoreScope.SCAN,
            scope_value=scan_key,
            findings=findings,
            computed_at=computed_at,
            scan_key=scan_key,
        )
        framework_scores = scores_by_dimension(
            tenant_id=tenant_id,
            scope=ScoreScope.FRAMEWORK,
            findings=findings,
            computed_at=computed_at,
            scan_key=scan_key,
        )
        domain_scores = scores_by_dimension(
            tenant_id=tenant_id,
            scope=ScoreScope.DOMAIN,
            findings=findings,
            computed_at=computed_at,
            scan_key=scan_key,
        )

        scores = (scan_score, *framework_scores, *domain_scores)
        self._repository.save_all(tenant_id=tenant_id, scores=scores)
        return scores


class QueryScores:
    """``GET /api/v1/scores`` — one page of a tenant's scores.

    Serves the dashboard's trend line as well as its headline number:
    filtering by ``scope=framework&scope_value=iso_27001`` over a time
    window returns that framework's score at each scan, in order, which
    is a chart without any further computation.
    """

    def __init__(self, repository: ComplianceScoreRepository) -> None:
        self._repository = repository

    def execute(
        self,
        *,
        identity: AuthenticatedIdentity,
        filters: ScoreFilter | None = None,
        page: PageRequest | None = None,
    ) -> Page[ComplianceScore]:
        identity.require_role(Role.READER)
        return self._repository.search(
            tenant_id=identity.tenant_id,
            filters=filters or ScoreFilter(),
            page=page or PageRequest(),
        )


class GetLatestScore:
    """The current score for one scope — the dashboard's headline."""

    def __init__(self, repository: ComplianceScoreRepository) -> None:
        self._repository = repository

    def execute(
        self,
        *,
        identity: AuthenticatedIdentity,
        scope: ScoreScope,
        scope_value: str | None = None,
    ) -> ComplianceScore | None:
        identity.require_role(Role.READER)
        return self._repository.latest(
            tenant_id=identity.tenant_id, scope=scope, scope_value=scope_value
        )
