"""Gate for the AWS integration suite.

These tests exercise the REAL AWS collector against a REAL,
Terraform-provisioned AWS account (terraform/aws/) — unlike everything
under tests/unit/, which never touches AWS. They only run when
explicitly enabled, so `pytest tests/` and CI stay credential-free by
default; running the full suite with `pytest tests/ -q` will show these
as skipped, not failed, absent that opt-in.

To run this suite for real:

    cd terraform/aws/environments/test
    terraform apply
    export COMPLIANCEIQ_AWS_INTEGRATION_TESTS=1
    export COMPLIANCEIQ_TEST_TENANT_ID=complianceiq-test-tenant
    export COMPLIANCEIQ_TEST_REGION=$(terraform output -raw -state=terraform.tfstate ... )  # or just your configured aws_region
    export COMPLIANCEIQ_TEST_COMPLIANT_BUCKET=$(terraform output -raw compliant_bucket_name)
    export COMPLIANCEIQ_TEST_NONCOMPLIANT_BUCKET=$(terraform output -raw noncompliant_bucket_name)
    export COMPLIANCEIQ_TEST_COMPLIANT_SG_ID=$(terraform output -raw compliant_security_group_id)
    export COMPLIANCEIQ_TEST_NONCOMPLIANT_SG_ID=$(terraform output -raw noncompliant_security_group_id)
    export COMPLIANCEIQ_TEST_NONCOMPLIANT_IAM_USER=$(terraform output -raw noncompliant_iam_user_name)
    export COMPLIANCEIQ_TEST_NONCOMPLIANT_FULL_ADMIN_IAM_USER=$(terraform output -raw noncompliant_full_admin_iam_user_name)
    export COMPLIANCEIQ_TEST_COMPLIANT_KMS_KEY_ARN=$(terraform output -raw compliant_kms_key_arn)
    export COMPLIANCEIQ_TEST_NONCOMPLIANT_KMS_KEY_ARN=$(terraform output -raw noncompliant_kms_key_arn)
    export COMPLIANCEIQ_TEST_POLICY_PUBLIC_KMS_KEY_ARN=$(terraform output -raw policy_public_kms_key_arn)
    export COMPLIANCEIQ_TEST_CLOUDTRAIL_ARN=$(terraform output -raw cloudtrail_trail_arn)
    export COMPLIANCEIQ_TEST_POLICY_PUBLIC_BUCKET=$(terraform output -raw policy_public_bucket_name)
    export COMPLIANCEIQ_TEST_CHAINED_SG_ID=$(terraform output -raw chained_to_open_security_group_id)
    export COMPLIANCEIQ_TEST_COMPLIANT_EC2_INSTANCE_ID=$(terraform output -raw compliant_ec2_instance_id)
    export COMPLIANCEIQ_TEST_NONCOMPLIANT_EC2_INSTANCE_ID=$(terraform output -raw noncompliant_ec2_instance_id)
    python3 -m pytest tests/integration/aws -q

AWS authentication itself is not read from any of these variables — it
uses the normal AWS credential chain (env vars / profile / assumed
role), exactly like a real scan would (infrastructure/cloud/aws/session.py).
"""

from __future__ import annotations

import os

import pytest

_GATE_ENV_VAR = "COMPLIANCEIQ_AWS_INTEGRATION_TESTS"

REQUIRED_ENV_VARS = (
    "COMPLIANCEIQ_TEST_TENANT_ID",
    "COMPLIANCEIQ_TEST_REGION",
    "COMPLIANCEIQ_TEST_COMPLIANT_BUCKET",
    "COMPLIANCEIQ_TEST_NONCOMPLIANT_BUCKET",
    "COMPLIANCEIQ_TEST_COMPLIANT_SG_ID",
    "COMPLIANCEIQ_TEST_NONCOMPLIANT_SG_ID",
    "COMPLIANCEIQ_TEST_NONCOMPLIANT_IAM_USER",
    "COMPLIANCEIQ_TEST_NONCOMPLIANT_FULL_ADMIN_IAM_USER",
    "COMPLIANCEIQ_TEST_COMPLIANT_KMS_KEY_ARN",
    "COMPLIANCEIQ_TEST_NONCOMPLIANT_KMS_KEY_ARN",
    "COMPLIANCEIQ_TEST_POLICY_PUBLIC_KMS_KEY_ARN",
    "COMPLIANCEIQ_TEST_CLOUDTRAIL_ARN",
    "COMPLIANCEIQ_TEST_POLICY_PUBLIC_BUCKET",
    "COMPLIANCEIQ_TEST_CHAINED_SG_ID",
    "COMPLIANCEIQ_TEST_COMPLIANT_EC2_INSTANCE_ID",
    "COMPLIANCEIQ_TEST_NONCOMPLIANT_EC2_INSTANCE_ID",
)


def pytest_collection_modifyitems(config, items):
    if os.environ.get(_GATE_ENV_VAR):
        return

    skip_marker = pytest.mark.skip(
        reason=(
            f"AWS integration tests are opt-in — set {_GATE_ENV_VAR}=1 "
            "(and the terraform-output env vars documented in "
            "tests/integration/aws/conftest.py) after deploying "
            "terraform/aws/environments/test. See "
            "docs/architecture/phase-3-infrastructure.md."
        )
    )
    for item in items:
        if "tests/integration/aws" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def terraform_outputs() -> dict:
    missing = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
    if missing:
        pytest.fail(
            f"{_GATE_ENV_VAR} is set, but these terraform-output env vars are "
            f"missing: {', '.join(missing)}. See tests/integration/aws/conftest.py."
        )
    return {name: os.environ[name] for name in REQUIRED_ENV_VARS}
