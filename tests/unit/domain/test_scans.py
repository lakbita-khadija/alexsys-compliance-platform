from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from domain.scans.models import Scan, ScanCounts, ScanError, ScanStatus, ScanTarget
from domain.shared.enums import CloudProvider, Severity
from domain.shared.errors import InvalidScan, InvalidScanTarget
from domain.shared.identifiers import TenantId

TENANT = TenantId("acme")
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(minutes=5)

AWS_TARGET = ScanTarget(provider=CloudProvider.AWS, account_id="111111111111")
AZURE_TARGET = ScanTarget(
    provider=CloudProvider.AZURE, account_id="sub-guid-1", directory_id="aad-tenant-1"
)


def an_error(service="kms") -> ScanError:
    return ScanError(
        provider=CloudProvider.AWS,
        service=service,
        operation="ListKeys",
        error_code="AccessDeniedException",
        message="not authorized",
        occurred_at=START,
        retryable=False,
    )


def a_scan(target=AWS_TARGET) -> Scan:
    return Scan.create(tenant_id=TENANT, target=target, started_at=START)


class TestScanTarget:
    def test_aws_target_uses_account_id(self) -> None:
        assert AWS_TARGET.account_id == "111111111111"
        assert AWS_TARGET.directory_id is None

    def test_azure_target_uses_the_same_field_for_subscription(self) -> None:
        # The multi-cloud invariant: no provider-specific column.
        assert AZURE_TARGET.account_id == "sub-guid-1"
        assert AZURE_TARGET.directory_id == "aad-tenant-1"

    def test_scope_key_distinguishes_providers(self) -> None:
        same_id_aws = ScanTarget(provider=CloudProvider.AWS, account_id="x")
        same_id_azure = ScanTarget(provider=CloudProvider.AZURE, account_id="x")
        assert same_id_aws.scope_key != same_id_azure.scope_key

    def test_scope_key_distinguishes_accounts(self) -> None:
        a = ScanTarget(provider=CloudProvider.AWS, account_id="111111111111")
        b = ScanTarget(provider=CloudProvider.AWS, account_id="222222222222")
        assert a.scope_key != b.scope_key

    def test_scope_key_does_not_use_colon_separator(self) -> None:
        # ':' appears inside ARNs — the audit §3 lesson.
        assert ":" not in ScanTarget(provider=CloudProvider.AWS, account_id="1").scope_key

    def test_unknown_account_is_explicit(self) -> None:
        assert "unknown-account" in ScanTarget(provider=CloudProvider.AWS).scope_key

    def test_blank_account_id_rejected(self) -> None:
        with pytest.raises(InvalidScanTarget):
            ScanTarget(provider=CloudProvider.AWS, account_id="  ")

    def test_provider_must_be_enum(self) -> None:
        with pytest.raises(InvalidScanTarget):
            ScanTarget(provider="aws")  # type: ignore[arg-type]


class TestScanKeyDerivation:
    def test_key_is_deterministic(self) -> None:
        assert a_scan().scan_key == a_scan().scan_key

    def test_two_accounts_same_instant_do_not_collide(self) -> None:
        a = Scan.create(tenant_id=TENANT, target=AWS_TARGET, started_at=START)
        b = Scan.create(
            tenant_id=TENANT,
            target=ScanTarget(provider=CloudProvider.AWS, account_id="222222222222"),
            started_at=START,
        )
        assert a.scan_key != b.scan_key

    def test_two_tenants_do_not_collide(self) -> None:
        a = Scan.create(tenant_id=TENANT, target=AWS_TARGET, started_at=START)
        b = Scan.create(tenant_id=TenantId("globex"), target=AWS_TARGET, started_at=START)
        assert a.scan_key != b.scan_key

    def test_aws_and_azure_do_not_collide(self) -> None:
        a = Scan.create(tenant_id=TENANT, target=AWS_TARGET, started_at=START)
        b = Scan.create(tenant_id=TENANT, target=AZURE_TARGET, started_at=START)
        assert a.scan_key != b.scan_key

    def test_key_contains_no_random_component(self) -> None:
        keys = {Scan.create(tenant_id=TENANT, target=AWS_TARGET, started_at=START).scan_key for _ in range(50)}
        assert len(keys) == 1


class TestScanStateMachine:
    def test_new_scan_is_queued(self) -> None:
        assert a_scan().status is ScanStatus.QUEUED

    def test_queued_to_running(self) -> None:
        assert a_scan().start().status is ScanStatus.RUNNING

    def test_running_to_completed(self) -> None:
        done = a_scan().start().complete(completed_at=END, counts=ScanCounts())
        assert done.status is ScanStatus.COMPLETED
        assert done.completed_at == END

    def test_running_to_partial_requires_errors(self) -> None:
        scan = a_scan().start()
        with pytest.raises(InvalidScan, match="requires at least one ScanError"):
            scan.complete_partially(completed_at=END, counts=ScanCounts(), errors=())

    def test_partial_completion_records_the_errors(self) -> None:
        partial = a_scan().start().complete_partially(
            completed_at=END, counts=ScanCounts(), errors=(an_error(),)
        )
        assert partial.status is ScanStatus.PARTIAL
        assert len(partial.errors) == 1

    def test_a_scan_carrying_errors_cannot_be_completed_cleanly(self) -> None:
        # The "no hidden compliance" invariant at scan level: a scan that
        # failed to read KMS must never be reported as full coverage.
        running = a_scan().start()
        with_errors = replace(running, errors=(an_error(),))
        with pytest.raises(InvalidScan, match="cannot be COMPLETED"):
            with_errors.complete(completed_at=END, counts=ScanCounts())

    def test_running_to_failed(self) -> None:
        failed = a_scan().start().fail(completed_at=END, errors=(an_error(),))
        assert failed.status is ScanStatus.FAILED
        assert failed.errors

    def test_queued_can_be_cancelled(self) -> None:
        assert a_scan().cancel(completed_at=END).status is ScanStatus.CANCELLED

    def test_completed_is_terminal(self) -> None:
        done = a_scan().start().complete(completed_at=END, counts=ScanCounts())
        with pytest.raises(InvalidScan, match="terminal state"):
            done.start()

    def test_failed_is_terminal(self) -> None:
        failed = a_scan().start().fail(completed_at=END)
        with pytest.raises(InvalidScan):
            failed.complete(completed_at=END, counts=ScanCounts())

    def test_cannot_skip_from_queued_to_completed(self) -> None:
        with pytest.raises(InvalidScan, match="illegal scan transition"):
            a_scan().complete(completed_at=END, counts=ScanCounts())

    def test_transitions_return_new_objects(self) -> None:
        scan = a_scan()
        assert scan.start() is not scan
        assert scan.status is ScanStatus.QUEUED

    def test_terminal_status_requires_completed_at(self) -> None:
        with pytest.raises(InvalidScan, match="must have completed_at"):
            Scan(
                scan_key="k",
                tenant_id=TENANT,
                target=AWS_TARGET,
                status=ScanStatus.COMPLETED,
                started_at=START,
            )

    def test_non_terminal_status_forbids_completed_at(self) -> None:
        with pytest.raises(InvalidScan, match="must not have completed_at"):
            Scan(
                scan_key="k",
                tenant_id=TENANT,
                target=AWS_TARGET,
                status=ScanStatus.RUNNING,
                started_at=START,
                completed_at=END,
            )

    def test_completed_at_cannot_precede_started_at(self) -> None:
        with pytest.raises(InvalidScan, match="must not precede"):
            Scan(
                scan_key="k",
                tenant_id=TENANT,
                target=AWS_TARGET,
                status=ScanStatus.COMPLETED,
                started_at=END,
                completed_at=START,
            )

    def test_duration_is_computed(self) -> None:
        done = a_scan().start().complete(completed_at=END, counts=ScanCounts())
        assert done.duration_seconds == 300.0

    def test_duration_is_none_while_running(self) -> None:
        assert a_scan().start().duration_seconds is None


class TestScanCounts:
    def _finding(self, status, severity):
        class F:
            pass

        f = F()
        f.status = type("S", (), {"value": status})()
        f.severity = severity
        return f

    def test_counts_only_failing_findings_by_severity(self) -> None:
        findings = [
            self._finding("fail", Severity.CRITICAL),
            self._finding("pass", Severity.CRITICAL),
            self._finding("indeterminate", Severity.HIGH),
        ]
        counts = ScanCounts.from_scan_data(resources=[1, 2], findings=findings)
        assert counts.critical_count == 1  # NOT 2 — the passing one must not count
        assert counts.finding_count == 3
        assert counts.pass_count == 1
        assert counts.fail_count == 1
        assert counts.indeterminate_count == 1
        assert counts.resource_count == 2

    def test_empty_scan_counts_are_zero(self) -> None:
        counts = ScanCounts.from_scan_data(resources=[], findings=[])
        assert counts.finding_count == 0 and counts.resource_count == 0

    def test_errors_are_counted(self) -> None:
        counts = ScanCounts.from_scan_data(resources=[], findings=[], errors=[an_error(), an_error("ec2")])
        assert counts.error_count == 2

    def test_negative_counts_rejected(self) -> None:
        with pytest.raises(InvalidScan):
            ScanCounts(resource_count=-1)


class TestScanError:
    def test_valid_error(self) -> None:
        err = an_error()
        assert err.service == "kms"
        assert err.retryable is False

    def test_blank_service_rejected(self) -> None:
        with pytest.raises(InvalidScan):
            ScanError(
                provider=CloudProvider.AWS,
                service="  ",
                operation="op",
                error_code="c",
                message="m",
                occurred_at=START,
            )

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(InvalidScan):
            ScanError(
                provider=CloudProvider.AWS,
                service="kms",
                operation="op",
                error_code="c",
                message="m",
                occurred_at=datetime(2026, 1, 1),
            )


class TestDomainPurity:
    def test_scans_module_imports_no_persistence(self) -> None:
        import ast
        import inspect

        import domain.scans.models as m
        import domain.scans.lifecycle as lc

        for module in (m, lc):
            tree = ast.parse(inspect.getsource(module))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
                elif isinstance(node, ast.Import):
                    imported.update(a.name for a in node.names)
            forbidden = {"sqlalchemy", "psycopg", "alembic"}
            assert not any(any(f in name for f in forbidden) for name in imported), imported
