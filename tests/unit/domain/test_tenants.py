import pytest

from domain.shared.errors import TenantIsolationViolation
from domain.shared.identifiers import TenantId
from domain.tenants.isolation import ensure_same_tenant
from domain.tenants.tenant import InvalidTenant, Tenant


class TestTenant:
    def test_valid_tenant(self) -> None:
        tenant = Tenant(id=TenantId("acme"), name="Acme Corp")
        assert tenant.id == TenantId("acme")
        assert tenant.name == "Acme Corp"

    def test_tenant_requires_non_blank_name(self) -> None:
        with pytest.raises(InvalidTenant):
            Tenant(id=TenantId("acme"), name="   ")

    def test_tenant_is_immutable(self) -> None:
        tenant = Tenant(id=TenantId("acme"), name="Acme Corp")
        with pytest.raises(Exception):
            tenant.name = "Other"  # type: ignore[misc]


class TestEnsureSameTenant:
    def test_same_tenant_passes_silently(self) -> None:
        ensure_same_tenant(TenantId("acme"), TenantId("acme"))

    def test_different_tenants_raise_isolation_violation(self) -> None:
        with pytest.raises(TenantIsolationViolation):
            ensure_same_tenant(TenantId("acme"), TenantId("other"))

    def test_violation_message_mentions_context_when_provided(self) -> None:
        with pytest.raises(TenantIsolationViolation, match="graph node"):
            ensure_same_tenant(TenantId("acme"), TenantId("other"), context="graph node")
