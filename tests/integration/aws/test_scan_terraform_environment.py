"""End-to-end proof: Terraform-provisioned AWS resources -> AwsCollector
-> ScanCloudAccount -> real Findings. See conftest.py for how to enable
this suite; it is skipped by default.

This is the one place in the whole project that exercises the real
production wiring together: ``AwsSessionFactory`` -> ``AwsCollector``
-> ``YamlRuleCatalog`` -> ``ScanCloudAccount`` — no fakes, no mocks,
against the actual account ``terraform/aws/environments/test`` applied.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from application.scanning.dtos import ScanConfiguration
from application.scanning.scan_cloud_account import ScanCloudAccount
from domain.findings.models import FindingStatus
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.collector import AwsCollector
from infrastructure.cloud.aws.credentials import AwsCredentialConfig
from infrastructure.cloud.aws.session import AwsSessionFactory
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

RULES_DIR = Path(__file__).resolve().parents[3] / "rules" / "aws"

pytestmark = pytest.mark.aws_integration


@pytest.fixture(scope="session")
def scan_result(terraform_outputs):
    tenant_id = TenantId(terraform_outputs["COMPLIANCEIQ_TEST_TENANT_ID"])
    region = terraform_outputs["COMPLIANCEIQ_TEST_REGION"]

    session = AwsSessionFactory().create(AwsCredentialConfig(region=region))
    collector = AwsCollector(session=session, tenant_id=tenant_id)
    rule_catalog = YamlRuleCatalog(RULES_DIR)

    use_case = ScanCloudAccount(collector=collector, rule_catalog=rule_catalog)
    return use_case.run(
        tenant_id=tenant_id,
        provider=CloudProvider.AWS,
        credentials_reference="integration-test",
        scan_configuration=ScanConfiguration(),
        scanned_at=datetime.now(timezone.utc),
    )


def _resource(scan_result, resource_id: str):
    return next(r for r in scan_result.resources if r.resource_id == ResourceId(resource_id))


def _findings_for(scan_result, resource_id: str):
    return [f for f in scan_result.findings if f.resource_id == ResourceId(resource_id)]


class TestCollectorDiscoversTerraformResources:
    """Requirement 1: the collector can discover the Terraform-created
    resources.
    """

    def test_compliant_bucket_is_discovered(self, scan_result, terraform_outputs) -> None:
        bucket_name = terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_BUCKET"]
        assert any(r.resource_id == ResourceId(bucket_name) for r in scan_result.resources)

    def test_noncompliant_bucket_is_discovered(self, scan_result, terraform_outputs) -> None:
        bucket_name = terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_BUCKET"]
        assert any(r.resource_id == ResourceId(bucket_name) for r in scan_result.resources)

    def test_both_security_groups_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_TEST_COMPLIANT_SG_ID", "COMPLIANCEIQ_TEST_NONCOMPLIANT_SG_ID"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_noncompliant_iam_user_is_discovered(self, scan_result, terraform_outputs) -> None:
        user_name = terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_IAM_USER"]
        assert any(user_name in str(r.resource_id) for r in scan_result.resources if r.resource_type == "iam_user")

    def test_both_kms_keys_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_TEST_COMPLIANT_KMS_KEY_ARN", "COMPLIANCEIQ_TEST_NONCOMPLIANT_KMS_KEY_ARN"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_cloudtrail_trail_is_discovered(self, scan_result, terraform_outputs) -> None:
        trail_arn = terraform_outputs["COMPLIANCEIQ_TEST_CLOUDTRAIL_ARN"]
        assert any(r.resource_id == ResourceId(trail_arn) for r in scan_result.resources)


class TestNormalizedResourcesContainExpectedData:
    """Requirement 2: normalized resources contain the expected data."""

    def test_compliant_bucket_attributes(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_BUCKET"])
        assert resource.attributes["encrypted"] is True
        assert resource.attributes["public"] is False
        assert resource.attributes["versioning_enabled"] is True

    def test_noncompliant_bucket_attributes(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_BUCKET"])
        assert resource.attributes["public"] is True
        assert resource.attributes["encrypted"] is False

    def test_noncompliant_security_group_has_open_ssh(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_SG_ID"])
        assert 22 in resource.attributes["unrestricted_ingress_ports"]

    def test_compliant_security_group_has_no_unrestricted_ingress(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_SG_ID"])
        assert resource.attributes["has_unrestricted_ingress"] is False

    def test_noncompliant_kms_key_has_rotation_disabled(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_KMS_KEY_ARN"])
        assert resource.attributes["rotation_enabled"] is False

    def test_compliant_kms_key_has_rotation_enabled(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_KMS_KEY_ARN"])
        assert resource.attributes["rotation_enabled"] is True

    def test_cloudtrail_trail_is_multi_region_and_validated(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_CLOUDTRAIL_ARN"])
        assert resource.attributes["is_multi_region_trail"] is True
        assert resource.attributes["log_file_validation_enabled"] is True


class TestCompleteScanExecutes:
    """Requirement 3: the application can execute a complete scan."""

    def test_scan_result_has_resources_graph_and_findings(self, scan_result) -> None:
        assert len(scan_result.resources) > 0
        assert len(scan_result.graph.nodes) == len(scan_result.resources)
        assert len(scan_result.findings) > 0


class TestNonCompliantResourceProducesFinding:
    """Requirement 4: at least one intentionally non-compliant resource
    produces a finding.
    """

    def test_noncompliant_bucket_fails_the_public_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_BUCKET"])
        matching = [f for f in findings if f.rule_id.value == "s3-bucket-public"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_noncompliant_security_group_fails_the_ssh_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_SG_ID"])
        matching = [f for f in findings if f.rule_id.value == "security-group-ssh-open-to-world"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_noncompliant_kms_key_fails_the_rotation_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_KMS_KEY_ARN"])
        matching = [f for f in findings if f.rule_id.value == "kms-key-rotation-disabled"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL


class TestCompliantResourceProducesPass:
    """Requirement 5: at least one compliant resource produces PASS."""

    def test_compliant_bucket_passes_the_public_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_BUCKET"])
        matching = [f for f in findings if f.rule_id.value == "s3-bucket-public"]
        assert matching
        assert matching[0].status is FindingStatus.PASS

    def test_compliant_kms_key_passes_the_rotation_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_KMS_KEY_ARN"])
        matching = [f for f in findings if f.rule_id.value == "kms-key-rotation-disabled"]
        assert matching
        assert matching[0].status is FindingStatus.PASS


class TestIndeterminateIsNeverSilentlyConverted:
    """Requirement 6: no INDETERMINATE result is incorrectly converted."""

    def test_no_finding_status_is_outside_the_three_valid_values(self, scan_result) -> None:
        for finding in scan_result.findings:
            assert finding.status in (FindingStatus.PASS, FindingStatus.FAIL, FindingStatus.INDETERMINATE)

    def test_non_ec2_rules_are_indeterminate_not_silently_passed_on_ec2_instances(self, scan_result) -> None:
        # rules/aws/ec2.yaml (Phase 3B) does target real ec2_instance
        # fields now, so EC2 findings are no longer expected to be 100%
        # INDETERMINATE. What must still hold: rules from *other*
        # domains (s3/iam/network/cloudtrail/kms), whose fields don't
        # exist on an ec2_instance's attributes at all, must resolve to
        # INDETERMINATE for EC2 resources — never silently PASS/FAIL by
        # omission. The current Terraform test environment (Task #45)
        # provisions no EC2 instances, so this is a structural
        # (rule-catalog-only) guarantee, not one this fixture currently
        # exercises against real resources.
        ec2_rule_ids = {r.id for r in YamlRuleCatalog(RULES_DIR).load() if r.service == "ec2"}
        ec2_resource_ids = {r.resource_id for r in scan_result.resources if r.resource_type == "ec2_instance"}
        non_ec2_rule_findings_on_ec2 = [
            f
            for f in scan_result.findings
            if f.resource_id in ec2_resource_ids and f.rule_id not in ec2_rule_ids
        ]
        assert all(f.status is FindingStatus.INDETERMINATE for f in non_ec2_rule_findings_on_ec2)


class TestPhase3BScenarios:
    """Requirement 8 (Phase 3B): the new collector attributes,
    relationship-based rules, and account-level IAM checks added this
    phase all work end-to-end against real Terraform-provisioned
    resources — not just in unit tests with fake boto3 clients.
    """

    def test_ec2_instances_are_discovered(self, scan_result, terraform_outputs) -> None:
        for key in ("COMPLIANCEIQ_TEST_COMPLIANT_EC2_INSTANCE_ID", "COMPLIANCEIQ_TEST_NONCOMPLIANT_EC2_INSTANCE_ID"):
            assert any(r.resource_id == ResourceId(terraform_outputs[key]) for r in scan_result.resources)

    def test_noncompliant_ec2_instance_has_public_ip_and_no_instance_profile(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_EC2_INSTANCE_ID"])
        assert resource.attributes["public_ip"] is not None
        assert resource.attributes["instance_profile_arn"] is None
        assert resource.attributes["imds_v2_required"] is False

    def test_compliant_ec2_instance_has_instance_profile_and_imdsv2(self, scan_result, terraform_outputs) -> None:
        resource = _resource(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_COMPLIANT_EC2_INSTANCE_ID"])
        assert resource.attributes["public_ip"] is None
        assert resource.attributes["instance_profile_arn"] is not None
        assert resource.attributes["imds_v2_required"] is True

    def test_noncompliant_ec2_instance_fails_attached_to_open_security_group_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_EC2_INSTANCE_ID"])
        matching = [f for f in findings if f.rule_id.value == "ec2-instance-attached-to-open-security-group"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_chained_security_group_fails_allows_another_open_security_group_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_CHAINED_SG_ID"])
        matching = [f for f in findings if f.rule_id.value == "security-group-allows-another-open-security-group"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_policy_public_bucket_fails_bucket_policy_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_POLICY_PUBLIC_BUCKET"])
        matching = [f for f in findings if f.rule_id.value == "s3-bucket-policy-allows-public-access"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_policy_public_kms_key_fails_key_policy_rule(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_POLICY_PUBLIC_KMS_KEY_ARN"])
        matching = [f for f in findings if f.rule_id.value == "kms-key-policy-allows-public-access"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_full_admin_iam_user_fails_full_admin_policy_rule(self, scan_result, terraform_outputs) -> None:
        user_name = terraform_outputs["COMPLIANCEIQ_TEST_NONCOMPLIANT_FULL_ADMIN_IAM_USER"]
        resource = next(
            r for r in scan_result.resources if r.resource_type == "iam_user" and user_name in str(r.resource_id)
        )
        findings = _findings_for(scan_result, str(resource.resource_id))
        matching = [f for f in findings if f.rule_id.value == "iam-user-full-admin-policy-attached"]
        assert matching
        assert matching[0].status is FindingStatus.FAIL

    def test_account_password_policy_passes_its_rules(self, scan_result) -> None:
        account_summary = next(r for r in scan_result.resources if r.resource_type == "iam_account_summary")
        findings = [f for f in scan_result.findings if f.resource_id == account_summary.resource_id]
        password_policy_findings = [f for f in findings if f.rule_id.value.startswith("iam-account-password-policy")]
        assert password_policy_findings
        assert all(f.status is FindingStatus.PASS for f in password_policy_findings)

    def test_cloudtrail_logs_to_a_versioned_non_public_bucket(self, scan_result, terraform_outputs) -> None:
        findings = _findings_for(scan_result, terraform_outputs["COMPLIANCEIQ_TEST_CLOUDTRAIL_ARN"])
        non_versioned = [f for f in findings if f.rule_id.value == "cloudtrail-logs-to-non-versioned-bucket"]
        public = [f for f in findings if f.rule_id.value == "cloudtrail-logs-to-public-bucket"]
        assert non_versioned and non_versioned[0].status is FindingStatus.PASS
        assert public and public[0].status is FindingStatus.PASS


class TestTenantIsolationRemainsIntact:
    """Requirement 7: tenant isolation remains intact."""

    def test_every_resource_and_finding_belongs_to_the_requested_tenant(self, scan_result, terraform_outputs) -> None:
        tenant_id = TenantId(terraform_outputs["COMPLIANCEIQ_TEST_TENANT_ID"])
        assert all(r.tenant_id == tenant_id for r in scan_result.resources)
        assert all(f.tenant_id == tenant_id for f in scan_result.findings)
        assert scan_result.tenant_id == tenant_id
