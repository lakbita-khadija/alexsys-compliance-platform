"""End-to-end proof: Terraform-provisioned Azure resources ->
AzureCollector -> ScanCloudAccount -> real Findings. See conftest.py
for how to enable this suite; it is skipped by default.

The Azure counterpart of ``tests/integration/aws/test_scan_terraform_environment.py``,
and it proves the multi-cloud claim at the only level that really
counts: the SAME ``ScanCloudAccount`` use case, the SAME
``ResourceGraph``, and the SAME rule engine, driven by a different
collector against a different cloud, with no provider-specific code
anywhere above ``infrastructure/``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from application.rules.composite_rule_catalog import CompositeRuleCatalog
from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from domain.findings.models import FindingStatus
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.collector import AzureCollector
from infrastructure.cloud.azure.credentials import AzureCredentialConfig
from infrastructure.cloud.azure.session import AzureSessionFactory
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

_REPO_ROOT = Path(__file__).resolve().parents[3]
AWS_RULES_DIR = _REPO_ROOT / "rules" / "aws"
AZURE_RULES_DIR = _REPO_ROOT / "rules" / "azure"

pytestmark = pytest.mark.azure_integration


@pytest.fixture(scope="session")
def scan_result(terraform_outputs):
    tenant_id = TenantId(terraform_outputs["COMPLIANCEIQ_AZURE_TEST_TENANT_ID"])
    subscription_id = terraform_outputs["COMPLIANCEIQ_AZURE_SUBSCRIPTION_ID"]

    clients = AzureSessionFactory().create(AzureCredentialConfig(subscription_id=subscription_id))
    collector = AzureCollector(clients=clients, tenant_id=tenant_id)

    # Deliberately the FULL multi-cloud catalog, not just rules/azure/:
    # scanning an Azure subscription with the AWS rules loaded must
    # produce no AWS findings at all, which is what
    # `applies_to_resource_type` guarantees.
    rule_catalog = CompositeRuleCatalog(YamlRuleCatalog(AWS_RULES_DIR), YamlRuleCatalog(AZURE_RULES_DIR))

    use_case = ScanCloudAccount(collector=collector, rule_catalog=rule_catalog)
    return use_case.run(
        tenant_id=tenant_id,
        provider=CloudProvider.AZURE,
        credentials_reference="integration-test",
        scan_configuration=ScanConfiguration(),
        scanned_at=datetime.now(timezone.utc),
    )


def _resource(scan_result, resource_id: str):
    return next(r for r in scan_result.resources if r.resource_id == ResourceId(resource_id))


def _findings_for(scan_result, resource_id: str):
    return [f for f in scan_result.findings if f.resource_id == ResourceId(resource_id)]


class TestCollectorDiscoversTerraformResources:
    def test_both_storage_accounts_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_AZURE_COMPLIANT_STORAGE_ID", "COMPLIANCEIQ_AZURE_NONCOMPLIANT_STORAGE_ID"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_both_network_security_groups_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_AZURE_COMPLIANT_NSG_ID", "COMPLIANCEIQ_AZURE_NONCOMPLIANT_NSG_ID"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_both_virtual_machines_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_AZURE_COMPLIANT_VM_ID", "COMPLIANCEIQ_AZURE_NONCOMPLIANT_VM_ID"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_both_key_vaults_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_AZURE_COMPLIANT_KEY_VAULT_ID", "COMPLIANCEIQ_AZURE_NONCOMPLIANT_KEY_VAULT_ID"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_activity_log_setting_is_discovered(self, scan_result) -> None:
        assert any(r.resource_type == "azure_activity_log_setting" for r in scan_result.resources)


class TestNormalizedResourcesContainExpectedData:
    def test_compliant_storage_account_attributes(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_COMPLIANT_STORAGE_ID"])
        assert resource.attributes["https_only"] is True
        assert resource.attributes["allow_blob_public_access"] is False
        assert resource.attributes["network_default_action"] == "Deny"

    def test_noncompliant_storage_account_attributes(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_STORAGE_ID"])
        assert resource.attributes["https_only"] is False
        assert resource.attributes["allow_blob_public_access"] is True
        assert resource.attributes["network_default_action"] == "Allow"

    def test_noncompliant_nsg_has_open_ssh_and_rdp(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_NSG_ID"])
        assert resource.attributes["has_unrestricted_ingress"] is True
        assert 22 in resource.attributes["unrestricted_ingress_ports"]
        assert 3389 in resource.attributes["unrestricted_ingress_ports"]

    def test_compliant_nsg_has_no_unrestricted_ingress(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_COMPLIANT_NSG_ID"])
        assert resource.attributes["has_unrestricted_ingress"] is False

    def test_deny_rules_are_not_counted_as_unrestricted_ingress(self, scan_result, terraform_outputs) -> None:
        # The non-compliant NSG carries a wildcard-source DENY rule
        # specifically to prove the normalizer ignores Deny rules; its
        # flag must come from the Allow rules only.
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_NSG_ID"])
        assert set(resource.attributes["unrestricted_ingress_ports"]) == {22, 3389}

    def test_noncompliant_vm_has_public_ip_and_no_managed_identity(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_VM_ID"])
        assert resource.attributes["public_ip_address"] is not None
        assert resource.attributes["system_assigned_identity_enabled"] is False

    def test_compliant_vm_has_managed_identity_and_no_public_ip(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_COMPLIANT_VM_ID"])
        assert resource.attributes["public_ip_address"] is None
        assert resource.attributes["system_assigned_identity_enabled"] is True

    def test_noncompliant_key_vault_attributes(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_KEY_VAULT_ID"])
        assert resource.attributes["rbac_authorization_enabled"] is False
        assert resource.attributes["network_default_action"] == "Allow"

    def test_every_resource_is_subscription_qualified(self, scan_result, terraform_outputs) -> None:
        subscription_id = terraform_outputs["COMPLIANCEIQ_AZURE_SUBSCRIPTION_ID"]
        assert all(r.account_id == subscription_id for r in scan_result.resources)

    def test_every_resource_is_marked_as_azure(self, scan_result) -> None:
        assert all(r.cloud_provider is CloudProvider.AZURE for r in scan_result.resources)


class TestCompleteScanExecutes:
    def test_scan_result_has_resources_graph_and_findings(self, scan_result) -> None:
        assert len(scan_result.resources) > 0
        assert len(scan_result.graph.nodes) == len(scan_result.resources)
        assert len(scan_result.findings) > 0


class TestNonCompliantResourceProducesFinding:
    def test_noncompliant_storage_fails_the_anonymous_access_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_STORAGE_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-storage-account-allows-blob-public-access"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_noncompliant_nsg_fails_the_ssh_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_NSG_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-nsg-ssh-open-to-internet"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_noncompliant_key_vault_fails_the_public_access_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_KEY_VAULT_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-key-vault-public-network-access-enabled"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL


class TestCompliantResourceProducesPass:
    def test_compliant_storage_passes_the_anonymous_access_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_COMPLIANT_STORAGE_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-storage-account-allows-blob-public-access"]
        assert matching
        assert matching[0].status is FindingStatus.PASS

    def test_compliant_nsg_passes_the_ssh_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_COMPLIANT_NSG_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-nsg-ssh-open-to-internet"]
        assert matching
        assert matching[0].status is FindingStatus.PASS


class TestCrossResourceRulesWorkAgainstRealAzureData:
    def test_noncompliant_vm_fails_the_attached_open_nsg_relationship_rule(self, scan_result, terraform_outputs) -> None:
        # The Azure VM -> NSG association is indirect (VM -> NIC ->
        # subnet -> NSG); this proves the collector resolves that whole
        # chain and that the relationship DSL evaluates it correctly
        # against real Azure data.
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_NONCOMPLIANT_VM_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-vm-attached-to-open-network-security-group"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_compliant_vm_passes_the_attached_open_nsg_relationship_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_AZURE_COMPLIANT_VM_ID"])
        matching = [f for f in findings if f.rule_id.value == "azure-vm-attached-to-open-network-security-group"]
        assert matching
        assert matching[0].status is FindingStatus.PASS

    def test_activity_log_passes_its_destination_relationship_rules(self, scan_result) -> None:
        setting = next(r for r in scan_result.resources if r.resource_type == "azure_activity_log_setting")
        findings = _findings_for(scan_result, str(setting.resource_id))
        relationship_rules = {
            "azure-activity-log-exports-to-publicly-exposed-storage",
            "azure-activity-log-exports-to-storage-without-soft-delete",
        }
        matching = [f for f in findings if f.rule_id.value in relationship_rules]
        assert matching
        assert all(f.status is FindingStatus.PASS for f in matching)


class TestMultiCloudIsolation:
    """The core multi-cloud invariant, proven against a real
    subscription: the AWS rules are loaded, and produce nothing.
    """

    def test_no_aws_rule_produces_a_finding_against_azure_resources(self, scan_result) -> None:
        aws_rule_ids = {str(r.id) for r in YamlRuleCatalog(AWS_RULES_DIR).load()}
        aws_findings = [f for f in scan_result.findings if str(f.rule_id) in aws_rule_ids]
        assert aws_findings == []

    def test_every_finding_comes_from_an_azure_rule(self, scan_result) -> None:
        azure_rule_ids = {str(r.id) for r in YamlRuleCatalog(AZURE_RULES_DIR).load()}
        assert all(str(f.rule_id) in azure_rule_ids for f in scan_result.findings)


class TestIndeterminateIsNeverSilentlyConverted:
    def test_no_finding_status_is_outside_the_three_valid_values(self, scan_result) -> None:
        for finding in scan_result.findings:
            assert finding.status in (FindingStatus.PASS, FindingStatus.FAIL, FindingStatus.INDETERMINATE)


class TestTenantIsolationRemainsIntact:
    def test_every_resource_and_finding_belongs_to_the_requested_tenant(self, scan_result, terraform_outputs) -> None:
        tenant_id = TenantId(terraform_outputs["COMPLIANCEIQ_AZURE_TEST_TENANT_ID"])
        assert all(r.tenant_id == tenant_id for r in scan_result.resources)
        assert all(f.tenant_id == tenant_id for f in scan_result.findings)
        assert scan_result.tenant_id == tenant_id
