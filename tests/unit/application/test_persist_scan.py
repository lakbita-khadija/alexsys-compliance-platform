"""Unit tests for ``PersistScanResult`` against in-memory fakes.

These prove the ORCHESTRATION: transaction boundary, lifecycle
reconciliation, tenant verification. Whether PostgreSQL actually honours
the transaction is a different question, answered by the real-database
integration tests in tests/integration/persistence/.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from application.ports.persistence.unit_of_work import UnitOfWork
from application.scanning.dtos import ScanResult
from application.scanning.persist_scan import PersistScanResult
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.graph.models import ResourceGraph
from domain.resources.models import NormalizedResource
from domain.scans.lifecycle import LifecycleState
from domain.scans.models import ScanError, ScanStatus, ScanTarget
from domain.shared.enums import CloudProvider, Severity
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId

TENANT = TenantId("acme")
OTHER_TENANT = TenantId("globex")
SCAN1_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCAN2_AT = SCAN1_AT + timedelta(days=1)
SCAN3_AT = SCAN1_AT + timedelta(days=2)
TARGET = ScanTarget(provider=CloudProvider.AWS, account_id="111111111111")


# ---------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------


class FakeScanRepo:
    def __init__(self, store):
        self._store = store

    def create(self, scan):
        self._store.setdefault("scans", {})[scan.scan_key] = scan

    def save(self, scan):
        self._store.setdefault("scans", {})[scan.scan_key] = scan

    def update_status(self, *, tenant_id, scan_key, status):
        pass

    def get(self, *, tenant_id, scan_key):
        return self._store.get("scans", {}).get(scan_key)

    def list_recent(self, *, tenant_id, limit=50, offset=0):
        return tuple(self._store.get("scans", {}).values())

    def record_errors(self, *, tenant_id, scan_key, errors):
        self._store.setdefault("errors", []).extend(errors)


class FakeResourceRepo:
    def __init__(self, store):
        self._store = store

    def save_all(self, *, tenant_id, scan_key, resources):
        self._store.setdefault("resources", []).extend(resources)
        return len(resources)

    def get_for_scan(self, *, tenant_id, scan_key):
        return tuple(self._store.get("resources", []))

    def get_resource_history(self, *, tenant_id, resource_id, limit=50):
        return ()


class FakeFindingRepo:
    def __init__(self, store):
        self._store = store

    def save_all(self, *, tenant_id, scan_key, findings):
        self._store.setdefault("findings", []).extend(findings)
        return len(findings)

    def get_for_scan(self, *, tenant_id, scan_key, status=None, severity=None):
        return tuple(self._store.get("findings", []))

    def get_by_id(self, *, tenant_id, finding_id):
        return None

    def get_history(self, *, tenant_id, logical_finding_id, limit=100):
        return ()


class FakeLogicalRepo:
    def __init__(self, store):
        self._store = store
        self._store.setdefault("logical", {})

    def get_active(self, *, tenant_id):
        return tuple(lf for lf in self._store["logical"].values() if lf.state.is_active)

    def get_by_logical_ids(self, *, tenant_id, logical_ids):
        return {lid: self._store["logical"][lid] for lid in logical_ids if lid in self._store["logical"]}

    def upsert_all(self, *, tenant_id, logical_findings):
        for lf in logical_findings:
            self._store["logical"][lf.logical_finding_id] = lf
        return len(logical_findings)

    def get_by_state(self, *, tenant_id, state, limit=100):
        return tuple(lf for lf in self._store["logical"].values() if lf.state is state)


class FakeAttackPathRepository:
    """Captures persisted attack paths for assertion."""

    def __init__(self) -> None:
        self.saved: list = []

    def save_all(self, *, tenant_id, scan_key, attack_paths, created_at) -> int:
        self.saved.extend(attack_paths)
        return len(attack_paths)

    def get_for_scan(self, *, tenant_id, scan_key):
        return ()

    def get_by_id(self, *, tenant_id, attack_path_id):
        return None


class FakeUnitOfWork(UnitOfWork):
    """Records commit/rollback so transaction semantics are assertable."""

    def __init__(self, store=None, fail_on=None):
        self.store = store if store is not None else {}
        self.committed = False
        self.rolled_back = False
        self._fail_on = fail_on
        self.scans = FakeScanRepo(self.store)
        self.resource_snapshots = FakeResourceRepo(self.store)
        self.finding_snapshots = FakeFindingRepo(self.store)
        self.logical_findings = FakeLogicalRepo(self.store)
        self.history = None
        # STEP 4: attack path persistence. Records what it was given so
        # a test can assert paths reach the repository, rather than
        # silently accepting them.
        self.attack_paths = FakeAttackPathRepository()
        if fail_on == "findings":
            self.finding_snapshots.save_all = self._boom  # type: ignore[method-assign]

    @staticmethod
    def _boom(**kwargs):
        raise RuntimeError("simulated persistence failure")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.committed:
            self.rolled_back = True

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


# ---------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------


def a_resource(resource_id="bucket-1", tenant=TENANT, collected_at=SCAN1_AT):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant,
        region="us-east-1",
        attributes={"public": True},
        tags={},
        relationships=(),
        collected_at=collected_at,
        account_id="111111111111",
    )


def a_finding(resource_id="bucket-1", rule="s3-bucket-public", status=FindingStatus.FAIL,
              detected_at=SCAN1_AT, tenant=TENANT, severity=Severity.CRITICAL):
    logical = f"{tenant!s}:111111111111:{resource_id}:{rule}"
    return Finding(
        id=FindingId(f"{logical}:{detected_at.isoformat()}"),
        tenant_id=tenant,
        resource_id=ResourceId(resource_id),
        rule_id=RuleId(rule),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        status=status,
        severity=severity,
        evidence=Evidence(data={"public": True}),
        detected_at=detected_at,
        account_id="111111111111",
        logical_finding_id=logical,
    )


def a_scan_result(
    resources=None, findings=None, scanned_at=SCAN1_AT, tenant=TENANT, provider=CloudProvider.AWS
):
    resources = tuple(resources if resources is not None else (a_resource(collected_at=scanned_at),))
    findings = tuple(findings if findings is not None else (a_finding(detected_at=scanned_at),))
    return ScanResult(
        scan_id=f"legacy:{scanned_at.isoformat()}",
        tenant_id=tenant,
        provider=provider,
        scanned_at=scanned_at,
        resources=resources,
        graph=ResourceGraph(tenant_id=tenant),
        findings=findings,
        attack_paths=(),
        drift_events=(),
    )


def persist(uow, scan_result, *, completed_at=None, errors=(), target=TARGET):
    return PersistScanResult(uow).execute(
        scan_result=scan_result,
        target=target,
        completed_at=completed_at or scan_result.scanned_at + timedelta(minutes=1),
        errors=errors,
    )


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


class TestBasicPersistence:
    def test_scan_is_persisted_and_completed(self) -> None:
        uow = FakeUnitOfWork()
        outcome = persist(uow, a_scan_result())
        assert outcome.status is ScanStatus.COMPLETED
        assert uow.committed is True

    def test_resources_and_findings_are_written(self) -> None:
        uow = FakeUnitOfWork()
        outcome = persist(uow, a_scan_result())
        assert outcome.resources_written == 1
        assert outcome.findings_written == 1

    def test_empty_scan_is_valid(self) -> None:
        uow = FakeUnitOfWork()
        outcome = persist(uow, a_scan_result(resources=(), findings=()))
        assert outcome.status is ScanStatus.COMPLETED
        assert outcome.resources_written == 0 and outcome.findings_written == 0
        assert uow.committed is True

    def test_scan_with_zero_findings_but_resources(self) -> None:
        uow = FakeUnitOfWork()
        outcome = persist(uow, a_scan_result(findings=()))
        assert outcome.resources_written == 1 and outcome.findings_written == 0

    def test_summary_counts_are_recorded_on_the_scan(self) -> None:
        uow = FakeUnitOfWork()
        outcome = persist(uow, a_scan_result())
        stored = uow.store["scans"][outcome.scan_key]
        assert stored.counts.fail_count == 1
        assert stored.counts.critical_count == 1
        assert stored.counts.resource_count == 1

    def test_duration_is_computed(self) -> None:
        uow = FakeUnitOfWork()
        outcome = persist(uow, a_scan_result(), completed_at=SCAN1_AT + timedelta(minutes=5))
        assert outcome.duration_seconds == 300.0


class TestPartialAndFailedScans:
    def test_errors_make_the_scan_partial_not_completed(self) -> None:
        uow = FakeUnitOfWork()
        error = ScanError(
            provider=CloudProvider.AWS,
            service="kms",
            operation="ListKeys",
            error_code="AccessDeniedException",
            message="denied",
            occurred_at=SCAN1_AT,
        )
        outcome = persist(uow, a_scan_result(), errors=(error,))
        assert outcome.status is ScanStatus.PARTIAL
        assert outcome.status is not ScanStatus.COMPLETED

    def test_partial_scan_errors_are_persisted(self) -> None:
        uow = FakeUnitOfWork()
        error = ScanError(
            provider=CloudProvider.AWS, service="kms", operation="ListKeys",
            error_code="AccessDeniedException", message="denied", occurred_at=SCAN1_AT,
        )
        persist(uow, a_scan_result(), errors=(error,))
        assert len(uow.store["errors"]) == 1

    def test_partial_scan_still_persists_the_findings_it_did_collect(self) -> None:
        uow = FakeUnitOfWork()
        error = ScanError(
            provider=CloudProvider.AWS, service="kms", operation="ListKeys",
            error_code="AccessDeniedException", message="denied", occurred_at=SCAN1_AT,
        )
        outcome = persist(uow, a_scan_result(), errors=(error,))
        assert outcome.findings_written == 1


class TestTransactionBoundary:
    def test_failure_mid_persist_rolls_back_and_does_not_commit(self) -> None:
        uow = FakeUnitOfWork(fail_on="findings")
        with pytest.raises(RuntimeError, match="simulated persistence failure"):
            persist(uow, a_scan_result())
        assert uow.committed is False
        assert uow.rolled_back is True

    def test_successful_persist_commits_exactly_once(self) -> None:
        uow = FakeUnitOfWork()
        persist(uow, a_scan_result())
        assert uow.committed is True
        assert uow.rolled_back is False


class TestTenantIsolation:
    def test_foreign_tenant_resource_is_refused(self) -> None:
        uow = FakeUnitOfWork()
        bad = a_scan_result(resources=(a_resource(tenant=OTHER_TENANT),))
        with pytest.raises(TenantIsolationViolation):
            persist(uow, bad)

    def test_foreign_tenant_finding_is_refused(self) -> None:
        uow = FakeUnitOfWork()
        bad = a_scan_result(findings=(a_finding(tenant=OTHER_TENANT),))
        with pytest.raises(TenantIsolationViolation):
            persist(uow, bad)

    def test_nothing_is_committed_when_tenant_check_fails(self) -> None:
        uow = FakeUnitOfWork()
        with pytest.raises(TenantIsolationViolation):
            persist(uow, a_scan_result(resources=(a_resource(tenant=OTHER_TENANT),)))
        assert uow.committed is False


class TestLifecycleReconciliation:
    """Part 7's four-scan scenario, driven through the use case."""

    def test_scan1_creates_an_open_lifecycle_row(self) -> None:
        uow = FakeUnitOfWork()
        persist(uow, a_scan_result())
        lf = list(uow.store["logical"].values())[0]
        assert lf.state is LifecycleState.OPEN
        assert lf.first_seen_scan_key == lf.last_seen_scan_key

    def test_scan2_still_failing_keeps_it_open_and_advances_last_seen(self) -> None:
        store = {}
        persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))
        outcome = persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN2_AT))
        lf = list(store["logical"].values())[0]
        assert lf.state is LifecycleState.OPEN
        assert lf.occurrence_count == 2
        assert lf.first_seen_scan_key != lf.last_seen_scan_key
        assert outcome.newly_resolved == 0 and outcome.newly_reopened == 0

    def test_scan3_absent_finding_resolves_it(self) -> None:
        store = {}
        persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))
        # Resource still scanned, but now compliant -> no failing finding.
        clean = a_scan_result(
            resources=(a_resource(collected_at=SCAN2_AT),),
            findings=(a_finding(status=FindingStatus.PASS, detected_at=SCAN2_AT),),
            scanned_at=SCAN2_AT,
        )
        outcome = persist(FakeUnitOfWork(store), clean)
        lf = list(store["logical"].values())[0]
        assert lf.state is LifecycleState.RESOLVED
        assert outcome.newly_resolved == 1

    def test_scan4_regression_reopens_the_same_logical_finding(self) -> None:
        store = {}
        persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))
        clean = a_scan_result(
            resources=(a_resource(collected_at=SCAN2_AT),),
            findings=(a_finding(status=FindingStatus.PASS, detected_at=SCAN2_AT),),
            scanned_at=SCAN2_AT,
        )
        persist(FakeUnitOfWork(store), clean)
        outcome = persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN3_AT))

        assert len(store["logical"]) == 1, "must be ONE logical finding across all four scans"
        lf = list(store["logical"].values())[0]
        assert lf.state is LifecycleState.REOPENED
        assert lf.reopen_count == 1
        assert lf.first_seen_at == SCAN1_AT, "original discovery date survives"
        assert outcome.newly_reopened == 1

    def test_finding_is_not_resolved_when_its_resource_was_not_scanned(self) -> None:
        # The critical precondition: a resource missing because
        # collection FAILED has not been fixed.
        store = {}
        persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))
        # Next scan sees a DIFFERENT resource entirely (bucket-1 not covered).
        other = a_scan_result(
            resources=(a_resource("bucket-2", collected_at=SCAN2_AT),),
            findings=(),
            scanned_at=SCAN2_AT,
        )
        outcome = persist(FakeUnitOfWork(store), other)
        lf = store["logical"][f"{TENANT!s}:111111111111:bucket-1:s3-bucket-public"]
        assert lf.state is LifecycleState.OPEN, "must NOT be resolved — it was never re-examined"
        assert outcome.newly_resolved == 0

    def test_passing_findings_never_create_lifecycle_rows(self) -> None:
        uow = FakeUnitOfWork()
        persist(uow, a_scan_result(findings=(a_finding(status=FindingStatus.PASS),)))
        assert uow.store["logical"] == {}

    def test_indeterminate_findings_never_create_lifecycle_rows(self) -> None:
        uow = FakeUnitOfWork()
        persist(uow, a_scan_result(findings=(a_finding(status=FindingStatus.INDETERMINATE),)))
        assert uow.store["logical"] == {}


class TestIdempotency:
    def test_persisting_the_same_scan_twice_is_safe(self) -> None:
        store = {}
        first = persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))
        second = persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))
        assert first.scan_key == second.scan_key, "same inputs -> same deterministic key"
        assert len(store["logical"]) == 1, "no duplicate lifecycle row"

    def test_scan_key_is_deterministic_across_runs(self) -> None:
        a = persist(FakeUnitOfWork(), a_scan_result(scanned_at=SCAN1_AT))
        b = persist(FakeUnitOfWork(), a_scan_result(scanned_at=SCAN1_AT))
        assert a.scan_key == b.scan_key


class TestMultiAccountAndMultiCloud:
    def test_same_resource_id_in_two_accounts_does_not_collide(self) -> None:
        store = {}
        uow = FakeUnitOfWork(store)
        # Same resource_id, different account -> different logical id.
        f1 = a_finding()
        f2 = Finding(
            id=FindingId("acme:222222222222:bucket-1:s3-bucket-public:x"),
            tenant_id=TENANT,
            resource_id=ResourceId("bucket-1"),
            rule_id=RuleId("s3-bucket-public"),
            framework="iso_27001",
            control_id="A.8.24",
            domain="storage",
            status=FindingStatus.FAIL,
            severity=Severity.CRITICAL,
            evidence=Evidence(data={}),
            detected_at=SCAN1_AT,
            account_id="222222222222",
            logical_finding_id="acme:222222222222:bucket-1:s3-bucket-public",
        )
        persist(uow, a_scan_result(findings=(f1, f2)))
        assert len(store["logical"]) == 2, "two accounts must yield two lifecycle rows"

    def test_scanning_another_account_does_not_resolve_this_accounts_finding(self) -> None:
        # Regression: resolution coverage was once keyed on resource_id
        # alone, so scanning account 222… "covered" bucket-1 and silently
        # resolved the *different* bucket-1 in account 111… — a live
        # security issue vanishing from the dashboard without being fixed.
        # Caught by the real-database suite; pinned here too.
        store = {}
        persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))

        other_account = NormalizedResource(
            resource_id=ResourceId("bucket-1"),
            resource_type="s3_bucket",
            cloud_provider=CloudProvider.AWS,
            tenant_id=TENANT,
            region="us-east-1",
            attributes={},
            tags={},
            relationships=(),
            collected_at=SCAN2_AT,
            account_id="222222222222",
        )
        persist(
            FakeUnitOfWork(store),
            a_scan_result(resources=(other_account,), findings=(), scanned_at=SCAN2_AT),
            target=ScanTarget(provider=CloudProvider.AWS, account_id="222222222222"),
        )

        lf = store["logical"][f"{TENANT!s}:111111111111:bucket-1:s3-bucket-public"]
        assert lf.state is LifecycleState.OPEN, "another account's scan must not resolve it"

    def test_scanning_azure_does_not_resolve_an_aws_finding(self) -> None:
        # Same guard on the provider axis: an Azure resource and an AWS
        # resource may share an id outright.
        store = {}
        persist(FakeUnitOfWork(store), a_scan_result(scanned_at=SCAN1_AT))

        azure_resource = NormalizedResource(
            resource_id=ResourceId("bucket-1"),
            resource_type="azure_storage_account",
            cloud_provider=CloudProvider.AZURE,
            tenant_id=TENANT,
            region="westeurope",
            attributes={},
            tags={},
            relationships=(),
            collected_at=SCAN2_AT,
            account_id="111111111111",
        )
        persist(
            FakeUnitOfWork(store),
            a_scan_result(
                resources=(azure_resource,),
                findings=(),
                scanned_at=SCAN2_AT,
                provider=CloudProvider.AZURE,
            ),
            target=ScanTarget(provider=CloudProvider.AZURE, account_id="111111111111"),
        )

        lf = store["logical"][f"{TENANT!s}:111111111111:bucket-1:s3-bucket-public"]
        assert lf.state is LifecycleState.OPEN, "an Azure scan must not resolve an AWS finding"


class TestArchitecturalPurity:
    def test_use_case_imports_no_infrastructure(self) -> None:
        import ast
        import inspect

        import application.scanning.persist_scan as module

        tree = ast.parse(inspect.getsource(module))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        assert not any(n.startswith("infrastructure") for n in imported)
        assert not any("sqlalchemy" in n or "psycopg" in n for n in imported)
