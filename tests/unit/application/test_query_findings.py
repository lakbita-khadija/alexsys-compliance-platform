from datetime import datetime, timezone

import pytest

from application.findings.finding_repository import FindingRepositoryPort
from application.findings.query_findings import QueryFindings
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.shared.enums import Severity
from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId

DETECTED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)
TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


def make_finding(finding_id="f-1", tenant_id=TENANT_A, status=FindingStatus.FAIL):
    return Finding(
        id=FindingId(finding_id),
        tenant_id=tenant_id,
        resource_id=ResourceId("bucket-1"),
        rule_id=RuleId("rule-1"),
        framework="iso_27001",
        control_id="A.8.24",
        domain="storage",
        status=status,
        severity=Severity.HIGH,
        evidence=Evidence(data={}),
        detected_at=DETECTED_AT,
    )


class FakeFindingRepository(FindingRepositoryPort):
    def __init__(self, findings):
        self._findings = tuple(findings)

    def query(self, tenant_id):
        return tuple(f for f in self._findings if f.tenant_id == tenant_id)


class TenantLeakingFakeRepository(FindingRepositoryPort):
    """Simulates a buggy adapter that ignores tenant scoping."""

    def __init__(self, findings):
        self._findings = tuple(findings)

    def query(self, tenant_id):
        return self._findings


class TestQueryFindings:
    def test_returns_findings_for_the_requested_tenant(self) -> None:
        repo = FakeFindingRepository([make_finding("f-1", TENANT_A), make_finding("f-2", TENANT_A)])
        findings = QueryFindings(repo).execute(tenant_id=TENANT_A)
        assert {f.id for f in findings} == {FindingId("f-1"), FindingId("f-2")}

    def test_does_not_return_other_tenants_findings(self) -> None:
        repo = FakeFindingRepository([make_finding("f-1", TENANT_A), make_finding("f-2", TENANT_B)])
        findings = QueryFindings(repo).execute(tenant_id=TENANT_A)
        assert [f.id for f in findings] == [FindingId("f-1")]

    def test_empty_repository_returns_empty_tuple(self) -> None:
        findings = QueryFindings(FakeFindingRepository([])).execute(tenant_id=TENANT_A)
        assert findings == ()

    def test_defense_in_depth_rejects_a_leaking_adapter(self) -> None:
        # Even if a buggy adapter returns cross-tenant data, the
        # application layer must not silently pass it through.
        repo = TenantLeakingFakeRepository([make_finding("f-1", TENANT_A), make_finding("f-2", TENANT_B)])
        with pytest.raises(TenantIsolationViolation):
            QueryFindings(repo).execute(tenant_id=TENANT_A)
