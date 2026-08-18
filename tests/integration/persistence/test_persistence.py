"""PostgreSQL persistence integration tests (Phase 4, Part 22).

These run against a REAL PostgreSQL server. Nothing here is faked with
dictionaries — the point is to exercise the semantics that only a real
database provides: JSONB round-tripping, ON CONFLICT upserts, CHECK
constraint enforcement, unique-constraint collisions, and genuine
transactional rollback.

Covers all 17 scenarios the brief enumerates, plus the tenant-isolation
proofs Part 16 requires.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from application.scanning.dtos import ScanResult
from application.scanning.persist_scan import PersistScanResult
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.graph.models import ResourceGraph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.scans.lifecycle import LifecycleState
from domain.scans.models import Scan, ScanError, ScanStatus, ScanTarget
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId

TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")
T1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
T2 = T1 + timedelta(days=1)
T3 = T1 + timedelta(days=2)

AWS_TARGET = ScanTarget(provider=CloudProvider.AWS, account_id="111111111111")
AWS_TARGET_B = ScanTarget(provider=CloudProvider.AWS, account_id="222222222222")
AZURE_TARGET = ScanTarget(provider=CloudProvider.AZURE, account_id="sub-1", directory_id="aad-1")


# ---------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------


def a_resource(resource_id="bucket-1", *, tenant=TENANT_A, account="111111111111",
               provider=CloudProvider.AWS, at=T1, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="s3_bucket",
        cloud_provider=provider,
        tenant_id=tenant,
        region="us-east-1",
        attributes=attributes if attributes is not None else {"public": True, "encrypted": False},
        tags={"env": "prod"},
        relationships=relationships,
        collected_at=at,
        account_id=account,
    )


def a_finding(resource_id="bucket-1", rule="s3-bucket-public", *, tenant=TENANT_A,
              account="111111111111", status=FindingStatus.FAIL, severity=Severity.CRITICAL,
              at=T1, evidence=None, related=(), indeterminate=(), graph_context=None):
    logical = f"{tenant!s}:{account}:{resource_id}:{rule}"
    return Finding(
        id=FindingId(f"{logical}:{at.isoformat()}"),
        tenant_id=tenant,
        resource_id=ResourceId(resource_id),
        rule_id=RuleId(rule),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        status=status,
        severity=severity,
        evidence=Evidence(data=evidence if evidence is not None else {"public": True, "narrative": "Bucket is public."}),
        detected_at=at,
        rule_version="1.1.0",
        region="us-east-1",
        account_id=account,
        logical_finding_id=logical,
        related_resources=related,
        indeterminate_resources=indeterminate,
        graph_context=graph_context,
    )


def a_scan_result(*, resources=None, findings=None, at=T1, tenant=TENANT_A,
                  provider=CloudProvider.AWS):
    return ScanResult(
        scan_id=f"legacy:{at.isoformat()}",
        tenant_id=tenant,
        provider=provider,
        scanned_at=at,
        resources=tuple(resources if resources is not None else (a_resource(at=at, tenant=tenant),)),
        graph=ResourceGraph(tenant_id=tenant),
        findings=tuple(findings if findings is not None else (a_finding(at=at, tenant=tenant),)),
        attack_paths=(),
        drift_events=(),
    )


def persist(uow, scan_result, *, target=AWS_TARGET, errors=(), completed_at=None):
    return PersistScanResult(uow).execute(
        scan_result=scan_result,
        target=target,
        completed_at=completed_at or scan_result.scanned_at + timedelta(minutes=2),
        errors=errors,
        scanner_version="4.0.0",
        ruleset_version="68-rules",
    )


# ---------------------------------------------------------------------
# 1-5: scan lifecycle and basic persistence
# ---------------------------------------------------------------------


class TestScanLifecycle:
    def test_1_and_2_scan_created_and_completed(self, uow) -> None:
        outcome = persist(uow, a_scan_result())
        assert outcome.status is ScanStatus.COMPLETED

        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored is not None
        assert stored.status is ScanStatus.COMPLETED
        assert stored.completed_at is not None
        assert stored.duration_seconds == 120.0
        assert stored.scanner_version == "4.0.0"

    def test_3_failed_scan_is_persisted_as_failed(self, uow, session_factory) -> None:
        scan = Scan.create(tenant_id=TENANT_A, target=AWS_TARGET, started_at=T1).start()
        failed = scan.fail(completed_at=T1 + timedelta(minutes=1))
        with uow as u:
            u.scans.create(scan)
            u.scans.save(failed)
            u.commit()

        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=scan.scan_key)
        assert stored.status is ScanStatus.FAILED

    def test_4_partial_scan_is_distinguishable_from_completed(self, uow) -> None:
        error = ScanError(
            provider=CloudProvider.AWS, service="kms", operation="ListKeys",
            error_code="AccessDeniedException", message="not authorized", occurred_at=T1,
        )
        outcome = persist(uow, a_scan_result(), errors=(error,))
        assert outcome.status is ScanStatus.PARTIAL

        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored.status is ScanStatus.PARTIAL
        assert stored.status is not ScanStatus.COMPLETED
        assert len(stored.errors) == 1
        assert stored.errors[0].service == "kms"
        assert stored.errors[0].error_code == "AccessDeniedException"
        assert stored.counts.error_count == 1

    def test_5_findings_are_persisted_with_full_fidelity(self, uow) -> None:
        outcome = persist(uow, a_scan_result())
        with uow as u:
            findings = u.finding_snapshots.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert len(findings) == 1
        f = findings[0]
        assert f.status is FindingStatus.FAIL
        assert f.severity is Severity.CRITICAL
        assert f.framework == "iso_27001"
        assert f.control_id == "A.8.24"
        assert f.rule_version == "1.1.0"
        assert f.account_id == "111111111111"
        assert f.logical_finding_id
        # JSONB round trip
        assert f.evidence.data["public"] is True
        assert f.evidence.data["narrative"] == "Bucket is public."

    def test_graph_context_survives_a_round_trip(self, uow, clean_db) -> None:
        """The graph is rebuilt per scan and never persisted.

        So if these columns did not round-trip, a finding read back
        tomorrow could not say which security group it matched — the
        graph that knew is gone. Asserted against a real database
        because a fake mapper cannot catch a missing column.
        """

        contextual = a_finding(
            related=("sg-open",),
            indeterminate=("sg-unreadable",),
            graph_context={
                "outgoing": [{"relationship": "attached_to", "target": "sg-open"}],
                "incoming": [],
                "is_internet_exposed": True,
            },
        )
        outcome = persist(uow, a_scan_result(findings=(contextual,)))
        with uow as u:
            stored = u.finding_snapshots.get_for_scan(
                tenant_id=TENANT_A, scan_key=outcome.scan_key
            )[0]

        assert stored.related_resources == ("sg-open",)
        assert stored.indeterminate_resources == ("sg-unreadable",)
        assert stored.graph_context is not None
        assert stored.graph_context["is_internet_exposed"] is True
        assert stored.graph_context["outgoing"][0]["target"] == "sg-open"

    def test_a_finding_without_context_round_trips_as_empty_not_null(
        self, uow, clean_db
    ) -> None:
        outcome = persist(uow, a_scan_result())
        with uow as u:
            stored = u.finding_snapshots.get_for_scan(
                tenant_id=TENANT_A, scan_key=outcome.scan_key
            )[0]
        # "Related to nothing" is the truthful value for a
        # single-resource rule, and it must not come back as None and
        # break the domain invariant on read.
        assert stored.related_resources == ()
        assert stored.indeterminate_resources == ()
        assert stored.graph_context is None

    def test_15_empty_scan_persists_cleanly(self, uow) -> None:
        outcome = persist(uow, a_scan_result(resources=(), findings=()))
        assert outcome.status is ScanStatus.COMPLETED
        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
            resources = u.resource_snapshots.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored.counts.resource_count == 0
        assert resources == ()

    def test_16_scan_with_resources_but_zero_findings(self, uow) -> None:
        outcome = persist(uow, a_scan_result(findings=()))
        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored.counts.resource_count == 1
        assert stored.counts.finding_count == 0


class TestResourceSnapshots:
    def test_resource_state_round_trips_including_jsonb(self, uow) -> None:
        resource = a_resource(
            attributes={"public": True, "nested": {"a": [1, 2, 3]}, "count": 42},
            relationships=(
                ResourceRelationship(
                    target_resource_id=ResourceId("sg-1"),
                    relationship_type=RelationshipType.ATTACHED_TO,
                ),
            ),
        )
        outcome = persist(uow, a_scan_result(resources=(resource,)))
        with uow as u:
            stored = u.resource_snapshots.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert len(stored) == 1
        r = stored[0]
        assert r.attributes["nested"] == {"a": [1, 2, 3]}
        assert r.attributes["count"] == 42
        assert r.tags == {"env": "prod"}
        assert len(r.relationships) == 1
        assert r.relationships[0].relationship_type is RelationshipType.ATTACHED_TO

    def test_resource_history_across_scans(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        persist(uow, a_scan_result(at=T2))
        with uow as u:
            history = u.resource_snapshots.get_resource_history(
                tenant_id=TENANT_A, resource_id=ResourceId("bucket-1")
            )
        assert len(history) == 2
        # Most recent first
        assert history[0][1].collected_at == T2


# ---------------------------------------------------------------------
# 6-8, 12: finding lifecycle across scans
# ---------------------------------------------------------------------


class TestFindingLifecycleAcrossScans:
    def test_6_and_12_finding_persists_as_one_logical_row_across_scans(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        persist(uow, a_scan_result(at=T2))

        with uow as u:
            active = u.logical_findings.get_active(tenant_id=TENANT_A)
        assert len(active) == 1, "the same issue across two scans must be ONE logical finding"
        lf = active[0]
        assert lf.state is LifecycleState.OPEN
        assert lf.occurrence_count == 2
        assert lf.first_seen_at == T1
        assert lf.last_seen_at == T2

    def test_7_finding_absent_from_a_covering_scan_is_resolved(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        clean = a_scan_result(
            at=T2,
            resources=(a_resource(at=T2),),
            findings=(a_finding(at=T2, status=FindingStatus.PASS),),
        )
        outcome = persist(uow, clean)
        assert outcome.newly_resolved == 1

        with uow as u:
            resolved = u.logical_findings.get_by_state(tenant_id=TENANT_A, state=LifecycleState.RESOLVED)
        assert len(resolved) == 1
        assert resolved[0].resolved_at == T2
        # NOT deleted — the history survives.
        assert resolved[0].first_seen_at == T1

    def test_8_regression_reopens_the_same_logical_finding(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        clean = a_scan_result(
            at=T2, resources=(a_resource(at=T2),),
            findings=(a_finding(at=T2, status=FindingStatus.PASS),),
        )
        persist(uow, clean)
        outcome = persist(uow, a_scan_result(at=T3))
        assert outcome.newly_reopened == 1

        with uow as u:
            active = u.logical_findings.get_active(tenant_id=TENANT_A)
        assert len(active) == 1
        lf = active[0]
        assert lf.state is LifecycleState.REOPENED
        assert lf.reopen_count == 1
        assert lf.first_seen_at == T1, "original discovery date survives the regression"
        assert lf.resolved_at is None

    def test_finding_history_lists_every_appearance(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        persist(uow, a_scan_result(at=T2))
        logical_id = f"{TENANT_A!s}:111111111111:bucket-1:s3-bucket-public"
        with uow as u:
            history = u.finding_snapshots.get_history(tenant_id=TENANT_A, logical_finding_id=logical_id)
        assert len(history) == 2
        assert history[0].scanned_at == T2  # newest first

    def test_rule_regressions_query(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        persist(uow, a_scan_result(
            at=T2, resources=(a_resource(at=T2),),
            findings=(a_finding(at=T2, status=FindingStatus.PASS),)))
        persist(uow, a_scan_result(at=T3))
        with uow as u:
            regressions = u.history.get_rule_regressions(tenant_id=TENANT_A)
        assert len(regressions) == 1
        assert regressions[0].reopen_count == 1


# ---------------------------------------------------------------------
# 9-11: isolation and multi-cloud
# ---------------------------------------------------------------------


class TestTenantIsolation:
    def test_9_two_tenants_are_fully_isolated(self, uow) -> None:
        persist(uow, a_scan_result(at=T1, tenant=TENANT_A))
        persist(uow, a_scan_result(
            at=T1, tenant=TENANT_B,
            resources=(a_resource(at=T1, tenant=TENANT_B),),
            findings=(a_finding(at=T1, tenant=TENANT_B),)))

        with uow as u:
            a_scans = u.scans.list_recent(tenant_id=TENANT_A)
            b_scans = u.scans.list_recent(tenant_id=TENANT_B)
            a_active = u.logical_findings.get_active(tenant_id=TENANT_A)
            b_active = u.logical_findings.get_active(tenant_id=TENANT_B)

        assert len(a_scans) == 1 and len(b_scans) == 1
        assert a_scans[0].scan_key != b_scans[0].scan_key
        assert all(s.tenant_id == TENANT_A for s in a_scans)
        assert all(s.tenant_id == TENANT_B for s in b_scans)
        assert all(f.tenant_id == TENANT_A for f in a_active)
        assert all(f.tenant_id == TENANT_B for f in b_active)

    def test_tenant_a_cannot_read_tenant_b_scan_by_key(self, uow) -> None:
        outcome = persist(uow, a_scan_result(at=T1, tenant=TENANT_B,
                                             resources=(a_resource(at=T1, tenant=TENANT_B),),
                                             findings=(a_finding(at=T1, tenant=TENANT_B),)))
        with uow as u:
            leaked = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert leaked is None, "knowing another tenant's scan_key must not grant access"

    def test_tenant_a_cannot_read_tenant_b_findings(self, uow) -> None:
        outcome = persist(uow, a_scan_result(at=T1, tenant=TENANT_B,
                                             resources=(a_resource(at=T1, tenant=TENANT_B),),
                                             findings=(a_finding(at=T1, tenant=TENANT_B),)))
        with uow as u:
            leaked = u.finding_snapshots.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert leaked == ()

    def test_persisting_a_foreign_tenant_resource_is_refused(self, uow) -> None:
        bad = a_scan_result(resources=(a_resource(tenant=TENANT_B),))
        with pytest.raises(TenantIsolationViolation):
            persist(uow, bad)


class TestMultiCloudAndMultiAccount:
    def test_10_aws_and_azure_coexist(self, uow) -> None:
        persist(uow, a_scan_result(at=T1), target=AWS_TARGET)

        azure_resource = NormalizedResource(
            resource_id=ResourceId("/subscriptions/sub-1/storageAccounts/st1"),
            resource_type="azure_storage_account",
            cloud_provider=CloudProvider.AZURE,
            tenant_id=TENANT_A, region="westeurope",
            attributes={"https_only": False}, tags={}, relationships=(),
            collected_at=T1, account_id="sub-1",
        )
        azure_finding = a_finding(
            resource_id="/subscriptions/sub-1/storageAccounts/st1",
            rule="azure-storage-account-https-not-enforced", account="sub-1", at=T1,
        )
        persist(uow,
                a_scan_result(at=T1, provider=CloudProvider.AZURE,
                              resources=(azure_resource,), findings=(azure_finding,)),
                target=AZURE_TARGET)

        with uow as u:
            scans = u.scans.list_recent(tenant_id=TENANT_A)
            active = u.logical_findings.get_active(tenant_id=TENANT_A)

        assert len(scans) == 2
        assert {s.target.provider for s in scans} == {CloudProvider.AWS, CloudProvider.AZURE}
        assert len(active) == 2
        assert {lf.provider for lf in active} == {CloudProvider.AWS, CloudProvider.AZURE}

    def test_11_same_resource_id_in_two_accounts_does_not_collide(self, uow) -> None:
        # Identical resource_id and rule, DIFFERENT account.
        persist(uow, a_scan_result(at=T1), target=AWS_TARGET)
        persist(uow,
                a_scan_result(at=T1,
                              resources=(a_resource(at=T1, account="222222222222"),),
                              findings=(a_finding(at=T1, account="222222222222"),)),
                target=AWS_TARGET_B)

        with uow as u:
            active = u.logical_findings.get_active(tenant_id=TENANT_A)
        assert len(active) == 2, "same resource id in two accounts = two distinct issues"
        assert {lf.account_id for lf in active} == {"111111111111", "222222222222"}

    def test_azure_directory_id_is_persisted(self, uow) -> None:
        outcome = persist(uow, a_scan_result(at=T1, provider=CloudProvider.AZURE,
                                             resources=(), findings=()),
                          target=AZURE_TARGET)
        with uow as u:
            stored = u.scans.get(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored.target.directory_id == "aad-1"
        assert stored.target.account_id == "sub-1"


# ---------------------------------------------------------------------
# 13-14, 17: transactions, idempotency, scale
# ---------------------------------------------------------------------


class TestTransactionsAndIdempotency:
    def test_13_rollback_on_persistence_failure_leaves_nothing_behind(self, uow, clean_db) -> None:
        scan_result = a_scan_result()

        class Boom(Exception):
            pass

        # Fail AFTER resources are written but BEFORE commit.
        original = uow.__class__.__enter__

        def enter_and_sabotage(self):
            u = original(self)
            real_save = u.finding_snapshots.save_all

            def exploding(**kwargs):
                real_save(**kwargs)
                raise Boom("failure after partial writes")

            u.finding_snapshots.save_all = exploding
            return u

        uow.__class__.__enter__ = enter_and_sabotage
        try:
            with pytest.raises(Boom):
                persist(uow, scan_result)
        finally:
            uow.__class__.__enter__ = original

        with clean_db.connect() as conn:
            scans = conn.execute(text("SELECT count(*) FROM scans")).scalar()
            resources = conn.execute(text("SELECT count(*) FROM resource_snapshots")).scalar()
            findings = conn.execute(text("SELECT count(*) FROM finding_snapshots")).scalar()
        assert (scans, resources, findings) == (0, 0, 0), "a failed persist must leave NOTHING"

    def test_14_persisting_the_same_scan_twice_is_safe(self, uow, clean_db) -> None:
        first = persist(uow, a_scan_result(at=T1))
        second = persist(uow, a_scan_result(at=T1))
        assert first.scan_key == second.scan_key

        with clean_db.connect() as conn:
            scans = conn.execute(text("SELECT count(*) FROM scans")).scalar()
            resources = conn.execute(text("SELECT count(*) FROM resource_snapshots")).scalar()
            findings = conn.execute(text("SELECT count(*) FROM finding_snapshots")).scalar()
            logical = conn.execute(text("SELECT count(*) FROM logical_findings")).scalar()
        assert (scans, resources, findings, logical) == (1, 1, 1, 1), "no duplicates"

    def test_17_large_finding_batch(self, uow, clean_db) -> None:
        # Exceeds BATCH_SIZE (1000) so the batching path is genuinely used.
        count = 2500
        resources = tuple(a_resource(f"bucket-{i}") for i in range(count))
        findings = tuple(a_finding(f"bucket-{i}") for i in range(count))
        outcome = persist(uow, a_scan_result(resources=resources, findings=findings))

        assert outcome.resources_written == count
        assert outcome.findings_written == count
        with clean_db.connect() as conn:
            stored = conn.execute(text("SELECT count(*) FROM finding_snapshots")).scalar()
            logical = conn.execute(text("SELECT count(*) FROM logical_findings")).scalar()
        assert stored == count
        assert logical == count


class TestDatabaseConstraints:
    """The CHECK/UNIQUE constraints must be enforced by PostgreSQL
    itself, not merely by the application.
    """

    def test_invalid_severity_is_rejected_by_the_database(self, clean_db) -> None:
        with pytest.raises(IntegrityError):
            with clean_db.begin() as conn:
                conn.execute(text("""
                    INSERT INTO scans (scan_key, tenant_id, provider, status, started_at,
                                       completed_at, created_at, scanner_version, ruleset_version, regions)
                    VALUES ('k','t','aws','completed', now(), now(), now(), 'v','v','[]'::jsonb)
                """))
                conn.execute(text("""
                    INSERT INTO finding_snapshots
                      (finding_id, scan_key, tenant_id, resource_id, rule_id, framework,
                       control_id, domain, status, severity, evidence, detected_at, version,
                       related_attack_path_ids, related_drift_event_ids)
                    VALUES ('f','k','t','r','rule','fw','c','d','fail','NOT_A_SEVERITY',
                            '{}'::jsonb, now(), 1, '[]'::jsonb, '[]'::jsonb)
                """))

    def test_invalid_scan_status_is_rejected(self, clean_db) -> None:
        with pytest.raises(IntegrityError):
            with clean_db.begin() as conn:
                conn.execute(text("""
                    INSERT INTO scans (scan_key, tenant_id, provider, status, started_at,
                                       created_at, scanner_version, ruleset_version, regions)
                    VALUES ('k2','t','aws','NOT_A_STATUS', now(), now(), 'v','v','[]'::jsonb)
                """))

    def test_terminal_scan_without_completed_at_is_rejected(self, clean_db) -> None:
        with pytest.raises(IntegrityError):
            with clean_db.begin() as conn:
                conn.execute(text("""
                    INSERT INTO scans (scan_key, tenant_id, provider, status, started_at,
                                       created_at, scanner_version, ruleset_version, regions)
                    VALUES ('k3','t','aws','completed', now(), now(), 'v','v','[]'::jsonb)
                """))

    def test_duplicate_logical_finding_identity_is_rejected(self, uow, clean_db) -> None:
        persist(uow, a_scan_result(at=T1))
        # Same (tenant, provider, account, resource, rule) but a
        # different logical_finding_id string -> must violate
        # uq_logical_finding_identity.
        with pytest.raises(IntegrityError):
            with clean_db.begin() as conn:
                conn.execute(text("""
                    INSERT INTO logical_findings
                      (logical_finding_id, tenant_id, provider, account_id, resource_id, rule_id,
                       state, severity, first_seen_at, last_seen_at, first_seen_scan_key,
                       last_seen_scan_key, reopen_count, occurrence_count, updated_at)
                    VALUES ('a-different-string','acme','aws','111111111111','bucket-1',
                            's3-bucket-public','open','critical', now(), now(), 's','s',0,1, now())
                """))


class TestComplianceHistory:
    def test_compliance_snapshot_for_a_scan(self, uow) -> None:
        findings = (
            a_finding("bucket-1", status=FindingStatus.FAIL, severity=Severity.CRITICAL),
            a_finding("bucket-2", status=FindingStatus.PASS, severity=Severity.HIGH),
            a_finding("bucket-3", status=FindingStatus.PASS, severity=Severity.LOW),
            a_finding("bucket-4", status=FindingStatus.INDETERMINATE, severity=Severity.MEDIUM),
        )
        resources = tuple(a_resource(f"bucket-{i}") for i in range(1, 5))
        outcome = persist(uow, a_scan_result(resources=resources, findings=findings))

        with uow as u:
            snap = u.history.get_compliance_snapshot(tenant_id=TENANT_A, scan_key=outcome.scan_key)

        assert snap is not None
        assert snap.fail_count == 1
        assert snap.pass_count == 2
        assert snap.indeterminate_count == 1
        assert snap.critical_count == 1
        # 2 pass / (2 pass + 1 fail) = 66.67 — INDETERMINATE excluded,
        # never counted as a pass.
        assert snap.score == 66.67

    def test_compliance_score_is_none_when_nothing_determinate(self, uow) -> None:
        findings = (a_finding("bucket-1", status=FindingStatus.INDETERMINATE),)
        outcome = persist(uow, a_scan_result(findings=findings))
        with uow as u:
            snap = u.history.get_compliance_snapshot(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert snap.score is None, "unknown must be honest, never a misleading 100%"

    def test_compliance_history_is_ordered_newest_first(self, uow) -> None:
        persist(uow, a_scan_result(at=T1))
        persist(uow, a_scan_result(at=T2))
        persist(uow, a_scan_result(at=T3))
        with uow as u:
            history = u.history.get_compliance_history(tenant_id=TENANT_A)
        assert len(history) == 3
        assert [h.scanned_at for h in history] == [T3, T2, T1]

    def test_compliance_history_filtered_by_provider(self, uow) -> None:
        persist(uow, a_scan_result(at=T1), target=AWS_TARGET)
        persist(uow, a_scan_result(at=T2, provider=CloudProvider.AZURE, resources=(), findings=()),
                target=AZURE_TARGET)
        with uow as u:
            aws_only = u.history.get_compliance_history(tenant_id=TENANT_A, provider=CloudProvider.AWS)
        assert len(aws_only) == 1
        assert aws_only[0].provider is CloudProvider.AWS

    def test_findings_breakdown_by_dimension(self, uow) -> None:
        findings = (
            a_finding("b1", severity=Severity.CRITICAL),
            a_finding("b2", severity=Severity.CRITICAL),
            a_finding("b3", severity=Severity.HIGH),
            a_finding("b4", status=FindingStatus.PASS, severity=Severity.LOW),
        )
        resources = tuple(a_resource(f"b{i}") for i in range(1, 5))
        outcome = persist(uow, a_scan_result(resources=resources, findings=findings))
        with uow as u:
            breakdown = u.history.count_findings_by(
                tenant_id=TENANT_A, scan_key=outcome.scan_key, dimension="severity"
            )
        counts = {b.value: b.count for b in breakdown}
        assert counts == {"critical": 2, "high": 1}, "PASS findings must not be counted"

    def test_unsupported_breakdown_dimension_is_rejected(self, uow) -> None:
        outcome = persist(uow, a_scan_result())
        with uow as u:
            with pytest.raises(ValueError, match="unsupported dimension"):
                u.history.count_findings_by(
                    tenant_id=TENANT_A, scan_key=outcome.scan_key, dimension="drop table"
                )


class TestSecretRedaction:
    """Part 20: credentials must never reach the database."""

    def test_secret_shaped_attributes_are_redacted(self, uow) -> None:
        resource = a_resource(attributes={
            "public": True,
            "aws_secret_access_key": "AKIAIOSFODNN7EXAMPLE",
            "client_secret": "super-secret-value",
            "nested": {"password": "hunter2"},
        })
        outcome = persist(uow, a_scan_result(resources=(resource,)))
        with uow as u:
            stored = u.resource_snapshots.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        attrs = stored[0].attributes
        assert attrs["aws_secret_access_key"] == "[REDACTED]"
        assert attrs["client_secret"] == "[REDACTED]"
        assert attrs["nested"]["password"] == "[REDACTED]"
        assert attrs["public"] is True, "non-secret data is untouched"

    def test_no_secret_material_is_present_anywhere_in_the_database(self, uow, clean_db) -> None:
        resource = a_resource(attributes={"aws_secret_access_key": "AKIAIOSFODNN7EXAMPLE"})
        finding = a_finding(evidence={"token": "ghp_realtokenvalue", "public": True})
        persist(uow, a_scan_result(resources=(resource,), findings=(finding,)))

        with clean_db.connect() as conn:
            resource_json = conn.execute(text("SELECT attributes::text FROM resource_snapshots")).scalar()
            evidence_json = conn.execute(text("SELECT evidence::text FROM finding_snapshots")).scalar()
        assert "AKIAIOSFODNN7EXAMPLE" not in resource_json
        assert "ghp_realtokenvalue" not in evidence_json

    def test_benign_keys_containing_key_are_not_redacted(self, uow) -> None:
        resource = a_resource(attributes={"access_key_count": 2, "kms_key_id": "arn:aws:kms:x"})
        outcome = persist(uow, a_scan_result(resources=(resource,)))
        with uow as u:
            stored = u.resource_snapshots.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert stored[0].attributes["access_key_count"] == 2
        assert stored[0].attributes["kms_key_id"] == "arn:aws:kms:x"
