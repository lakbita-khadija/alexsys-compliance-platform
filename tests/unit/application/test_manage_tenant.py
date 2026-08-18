import pytest

from application.tenants.manage_tenant import ManageTenant
from domain.shared.identifiers import TenantId
from domain.tenants.tenant import InvalidTenant, Tenant


class TestManageTenantRegister:
    def test_registers_a_valid_tenant(self) -> None:
        tenant = ManageTenant().register(tenant_id="acme", name="Acme Corp")
        assert tenant == Tenant(id=TenantId("acme"), name="Acme Corp")

    def test_delegates_validation_to_the_domain_entity(self) -> None:
        with pytest.raises(InvalidTenant):
            ManageTenant().register(tenant_id="acme", name="   ")

    def test_registration_is_deterministic(self) -> None:
        results = {ManageTenant().register(tenant_id="acme", name="Acme Corp") for _ in range(10)}
        assert len(results) == 1
