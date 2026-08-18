"""Phase 5 repositories against real PostgreSQL.

The in-memory adapters make the API suite fast, but they are Python
dicts — they cannot tell us whether the SQL filters correctly, whether
the unique index actually deduplicates, or whether `= NULL` silently
matches nothing. Those are exactly the mistakes that pass every unit
test and fail in production, so they are tested here against a real
server.

Auto-skips when PostgreSQL is unreachable, like the rest of this package.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from application.ports.queries import (
    FindingFilter,
    PageRequest,
    ScoreFilter,
    SortOrder,
)
from domain.audit.models import AuditAction, AuditActor, AuditEvent
from domain.compliance.scoring import ComplianceScore, ScoreCounts, ScoreScope
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.shared.enums import Severity
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId
from infrastructure.persistence.postgres.mappers.mappers import finding_to_row, scan_to_row
from infrastructure.persistence.postgres.models.tables import PostgresFindingSnapshotModel
from infrastructure.persistence.postgres.repositories.api_repositories import (
    PostgresAuditEventRepository,
    PostgresComplianceScoreRepository,
    PostgresFindingQueryRepository,
)

TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")
T1 = datetime(2026, 5, 1, tzinfo=timezone.utc)


def a_finding(
    *,
    tenant=TENANT_A,
    resource="bucket-1",
    rule="s3-public",
    status=FindingStatus.FAIL,
    severity=Severity.CRITICAL,
    framework="iso_27001",
    domain="storage",
    at=T1,
    suffix="",
) -> Finding:
    logical = f"{tenant!s}:111111111111:{resource}:{rule}"
    return Finding(
        id=FindingId(f"{logical}:{at.isoformat()}{suffix}"),
        tenant_id=tenant,
        resource_id=ResourceId(resource),
        rule_id=RuleId(rule),
        framework=framework,
        control_id="A.8.24",
        domain=domain,
        status=status,
        severity=severity,
        evidence=Evidence(data={"public": True}),
        detected_at=at,
        account_id="111111111111",
        logical_finding_id=logical,
    )


@pytest.fixture()
def seeded(session_factory):
    """Findings for two tenants, sharing resource ids and rules."""

    from domain.scans.models import Scan, ScanTarget
    from domain.shared.enums import CloudProvider

    session = session_factory()
    scan_key = "seed-scan"
    scan = Scan.create(
        tenant_id=TENANT_A,
        target=ScanTarget(provider=CloudProvider.AWS, account_id="111111111111"),
        started_at=T1,
    )
    row = scan_to_row(scan)
    row["scan_key"] = scan_key
    session.execute(
        __import__("sqlalchemy").insert(
            __import__(
                "infrastructure.persistence.postgres.models.tables",
                fromlist=["PostgresScanModel"],
            ).PostgresScanModel
        ).values(row)
    )

    findings = [
        a_finding(),
        a_finding(resource="bucket-2", severity=Severity.HIGH, suffix="-b"),
        a_finding(resource="bucket-3", status=FindingStatus.PASS, severity=Severity.LOW, suffix="-c"),
        a_finding(
            resource="bucket-4",
            status=FindingStatus.INDETERMINATE,
            severity=Severity.MEDIUM,
            domain="encryption",
            at=T1 + timedelta(days=1),
            suffix="-d",
        ),
        a_finding(tenant=TENANT_B, suffix="-t2"),
    ]
    for finding in findings:
        session.execute(
            __import__("sqlalchemy").insert(PostgresFindingSnapshotModel).values(
                finding_to_row(finding, scan_key=scan_key)
            )
        )
    session.commit()
    yield session
    session.close()


class TestFindingQueries:
    def test_tenant_scoping_is_enforced_in_sql(self, seeded) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        page = repo.search(tenant_id=TENANT_A, filters=FindingFilter(), page=PageRequest())
        assert page.total == 4
        assert {str(f.tenant_id) for f in page.items} == {"acme"}

    def test_another_tenants_finding_is_not_retrievable_by_id(self, seeded) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        foreign = f"{TENANT_B!s}:111111111111:bucket-1:s3-public:{T1.isoformat()}-t2"
        assert repo.get(tenant_id=TENANT_B, finding_id=foreign) is not None
        assert repo.get(tenant_id=TENANT_A, finding_id=foreign) is None

    @pytest.mark.parametrize(
        "filters,expected",
        [
            (FindingFilter(severity=Severity.CRITICAL), 1),
            (FindingFilter(status=FindingStatus.FAIL), 2),
            (FindingFilter(status=FindingStatus.INDETERMINATE), 1),
            (FindingFilter(domain="storage"), 3),
            (FindingFilter(framework="iso_27001"), 4),
            (FindingFilter(resource_id="bucket-2"), 1),
            (FindingFilter(rule_id="s3-public"), 4),
        ],
    )
    def test_filters_are_applied_in_sql(self, seeded, filters, expected) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        assert repo.search(tenant_id=TENANT_A, filters=filters, page=PageRequest()).total == expected

    def test_date_range_filtering(self, seeded) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        page = repo.search(
            tenant_id=TENANT_A,
            filters=FindingFilter(detected_after=T1 + timedelta(hours=1)),
            page=PageRequest(),
        )
        assert page.total == 1

    def test_pagination_does_not_load_everything(self, seeded) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        page = repo.search(
            tenant_id=TENANT_A, filters=FindingFilter(), page=PageRequest(limit=2, offset=0)
        )
        # total counts ALL matches; items is only the window.
        assert page.total == 4
        assert len(page.items) == 2
        assert page.has_more is True

    def test_pages_do_not_overlap(self, seeded) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        first = repo.search(tenant_id=TENANT_A, filters=FindingFilter(), page=PageRequest(limit=2))
        second = repo.search(
            tenant_id=TENANT_A, filters=FindingFilter(), page=PageRequest(limit=2, offset=2)
        )
        assert not {str(f.id) for f in first.items} & {str(f.id) for f in second.items}

    def test_severity_sort_is_by_rank_not_alphabetical(self, seeded) -> None:
        # Alphabetically "high" < "low" < "medium". If the ORDER BY used
        # the raw text, MEDIUM would outrank HIGH.
        repo = PostgresFindingQueryRepository(seeded)
        page = repo.search(
            tenant_id=TENANT_A,
            filters=FindingFilter(),
            page=PageRequest(),
            sort=SortOrder.SEVERITY_DESC,
        )
        severities = [f.severity for f in page.items]
        assert severities[0] is Severity.CRITICAL
        assert severities.index(Severity.HIGH) < severities.index(Severity.MEDIUM)

    def test_ordering_is_deterministic_across_calls(self, seeded) -> None:
        repo = PostgresFindingQueryRepository(seeded)
        a = repo.search(tenant_id=TENANT_A, filters=FindingFilter(), page=PageRequest())
        b = repo.search(tenant_id=TENANT_A, filters=FindingFilter(), page=PageRequest())
        assert [str(f.id) for f in a.items] == [str(f.id) for f in b.items]


class TestScoreRepository:
    def _score(self, *, scope, scope_value, scan_key="scan-1", passed=8, failed=2, at=T1):
        return ComplianceScore(
            tenant_id=TENANT_A,
            scope=scope,
            scope_value=scope_value,
            counts=ScoreCounts(passed=passed, failed=failed, indeterminate=1),
            computed_at=at,
            scan_key=scan_key,
        )

    def test_scores_round_trip(self, session_factory) -> None:
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        repo.save_all(
            tenant_id=TENANT_A,
            scores=[self._score(scope=ScoreScope.FRAMEWORK, scope_value="iso_27001")],
        )
        session.commit()

        page = repo.search(tenant_id=TENANT_A, filters=ScoreFilter(), page=PageRequest())
        assert page.total == 1
        assert page.items[0].score == 80.0
        assert page.items[0].coverage == pytest.approx(90.91, abs=0.01)
        session.close()

    def test_rescoring_the_same_scan_replaces_rather_than_duplicates(
        self, session_factory
    ) -> None:
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        repo.save_all(
            tenant_id=TENANT_A,
            scores=[self._score(scope=ScoreScope.FRAMEWORK, scope_value="iso_27001")],
        )
        session.commit()
        repo.save_all(
            tenant_id=TENANT_A,
            scores=[
                self._score(scope=ScoreScope.FRAMEWORK, scope_value="iso_27001", passed=9, failed=1)
            ],
        )
        session.commit()

        page = repo.search(tenant_id=TENANT_A, filters=ScoreFilter(), page=PageRequest())
        assert page.total == 1, "a retry must replace, not duplicate"
        assert page.items[0].score == 90.0
        session.close()

    def test_the_tenant_scope_row_deduplicates_despite_a_null_scope_value(
        self, session_factory
    ) -> None:
        # NULLS NOT DISTINCT is what makes this work. Under default SQL
        # NULL semantics every recompute would insert another row,
        # because NULL <> NULL.
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        for passed in (5, 7):
            repo.save_all(
                tenant_id=TENANT_A,
                scores=[self._score(scope=ScoreScope.TENANT, scope_value=None, passed=passed)],
            )
            session.commit()

        page = repo.search(
            tenant_id=TENANT_A, filters=ScoreFilter(scope=ScoreScope.TENANT), page=PageRequest()
        )
        assert page.total == 1
        session.close()

    def test_latest_finds_the_tenant_score_with_a_null_scope_value(
        self, session_factory
    ) -> None:
        # `= NULL` is never true in SQL. If the query used it instead of
        # `IS NULL`, the headline tenant score would always be missing.
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        repo.save_all(
            tenant_id=TENANT_A,
            scores=[self._score(scope=ScoreScope.TENANT, scope_value=None)],
        )
        session.commit()

        assert repo.latest(tenant_id=TENANT_A, scope=ScoreScope.TENANT) is not None
        session.close()

    def test_latest_returns_the_most_recent(self, session_factory) -> None:
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        repo.save_all(
            tenant_id=TENANT_A,
            scores=[
                self._score(scope=ScoreScope.SCAN, scope_value="s1", scan_key="s1", passed=5),
                self._score(
                    scope=ScoreScope.SCAN,
                    scope_value="s2",
                    scan_key="s2",
                    passed=10,
                    failed=0,
                    at=T1 + timedelta(days=1),
                ),
            ],
        )
        session.commit()

        latest = repo.latest(tenant_id=TENANT_A, scope=ScoreScope.SCAN, scope_value="s2")
        assert latest is not None and latest.score == 100.0
        session.close()

    def test_a_foreign_tenant_score_is_refused(self, session_factory) -> None:
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        foreign = ComplianceScore(
            tenant_id=TENANT_B,
            scope=ScoreScope.TENANT,
            scope_value=None,
            counts=ScoreCounts(passed=1),
            computed_at=T1,
        )
        with pytest.raises(TenantIsolationViolation):
            repo.save_all(tenant_id=TENANT_A, scores=[foreign])
        session.close()

    def test_scores_are_tenant_isolated(self, session_factory) -> None:
        session = session_factory()
        repo = PostgresComplianceScoreRepository(session)
        repo.save_all(
            tenant_id=TENANT_A, scores=[self._score(scope=ScoreScope.TENANT, scope_value=None)]
        )
        session.commit()

        assert (
            repo.search(tenant_id=TENANT_B, filters=ScoreFilter(), page=PageRequest()).total == 0
        )
        session.close()


class TestAuditRepository:
    def _event(self, *, tenant=TENANT_A, event_id="evt-1", action=AuditAction.SCAN_STARTED):
        return AuditEvent(
            event_id=event_id,
            tenant_id=tenant,
            actor=AuditActor(subject="ai-service"),
            action=action,
            occurred_at=T1,
            resource="scan-1",
            resource_type="scan",
            correlation_id="corr-1",
            metadata={"provider": "aws"},
        )

    def test_events_round_trip(self, session_factory) -> None:
        session = session_factory()
        repo = PostgresAuditEventRepository(session)
        repo.record(self._event())
        session.commit()

        page = repo.search(tenant_id=TENANT_A, page=PageRequest())
        assert page.total == 1
        assert page.items[0].action is AuditAction.SCAN_STARTED
        assert page.items[0].correlation_id == "corr-1"
        assert page.items[0].metadata["provider"] == "aws"
        session.close()

    def test_recording_the_same_event_twice_is_a_noop(self, session_factory) -> None:
        # A redelivered job must not fail the operation it is auditing.
        session = session_factory()
        repo = PostgresAuditEventRepository(session)
        repo.record(self._event())
        session.commit()
        repo.record(self._event())
        session.commit()

        assert repo.search(tenant_id=TENANT_A, page=PageRequest()).total == 1
        session.close()

    def test_audit_events_are_tenant_isolated(self, session_factory) -> None:
        session = session_factory()
        repo = PostgresAuditEventRepository(session)
        repo.record(self._event(tenant=TENANT_A, event_id="a1"))
        repo.record(self._event(tenant=TENANT_B, event_id="b1"))
        session.commit()

        assert repo.search(tenant_id=TENANT_A, page=PageRequest()).total == 1
        assert repo.search(tenant_id=TENANT_B, page=PageRequest()).total == 1
        session.close()

    def test_the_repository_exposes_no_mutation_path(self) -> None:
        # An audit trail that can be edited is not evidence.
        for forbidden in ("update", "delete", "remove", "purge"):
            assert not hasattr(PostgresAuditEventRepository, forbidden)
