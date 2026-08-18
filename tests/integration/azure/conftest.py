"""Gate for the Azure integration suite.

The Azure sibling of ``tests/integration/aws/conftest.py``, with the
same contract: these tests exercise the REAL ``AzureCollector`` against
a REAL, Terraform-provisioned Azure subscription. They only run when
explicitly enabled, so ``pytest tests/`` and CI stay credential-free by
default; running the full suite shows these as skipped, not failed,
absent that opt-in.

To run this suite for real:

    cd terraform/azure/environments/test
    az login
    terraform apply -var="admin_ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)"

    export COMPLIANCEIQ_AZURE_INTEGRATION_TESTS=1
    export COMPLIANCEIQ_AZURE_TEST_TENANT_ID=complianceiq-test-tenant
    export COMPLIANCEIQ_AZURE_SUBSCRIPTION_ID=$(terraform output -raw subscription_id)
    export COMPLIANCEIQ_AZURE_COMPLIANT_STORAGE_ID=$(terraform output -raw compliant_storage_account_id)
    export COMPLIANCEIQ_AZURE_NONCOMPLIANT_STORAGE_ID=$(terraform output -raw noncompliant_storage_account_id)
    export COMPLIANCEIQ_AZURE_AUDIT_LOGS_STORAGE_ID=$(terraform output -raw audit_logs_storage_account_id)
    export COMPLIANCEIQ_AZURE_COMPLIANT_NSG_ID=$(terraform output -raw compliant_nsg_id)
    export COMPLIANCEIQ_AZURE_NONCOMPLIANT_NSG_ID=$(terraform output -raw noncompliant_nsg_id)
    export COMPLIANCEIQ_AZURE_COMPLIANT_VM_ID=$(terraform output -raw compliant_vm_id)
    export COMPLIANCEIQ_AZURE_NONCOMPLIANT_VM_ID=$(terraform output -raw noncompliant_vm_id)
    export COMPLIANCEIQ_AZURE_COMPLIANT_KEY_VAULT_ID=$(terraform output -raw compliant_key_vault_id)
    export COMPLIANCEIQ_AZURE_NONCOMPLIANT_KEY_VAULT_ID=$(terraform output -raw noncompliant_key_vault_id)

    python3 -m pytest tests/integration/azure -q

Azure authentication itself is not read from any of these variables —
it uses ``DefaultAzureCredential``'s normal chain (environment
variables / managed identity / ``az login``), exactly like a real scan
would (infrastructure/cloud/azure/session.py).
"""

from __future__ import annotations

import os

import pytest

_GATE_ENV_VAR = "COMPLIANCEIQ_AZURE_INTEGRATION_TESTS"

REQUIRED_ENV_VARS = (
    "COMPLIANCEIQ_AZURE_TEST_TENANT_ID",
    "COMPLIANCEIQ_AZURE_SUBSCRIPTION_ID",
    "COMPLIANCEIQ_AZURE_COMPLIANT_STORAGE_ID",
    "COMPLIANCEIQ_AZURE_NONCOMPLIANT_STORAGE_ID",
    "COMPLIANCEIQ_AZURE_AUDIT_LOGS_STORAGE_ID",
    "COMPLIANCEIQ_AZURE_COMPLIANT_NSG_ID",
    "COMPLIANCEIQ_AZURE_NONCOMPLIANT_NSG_ID",
    "COMPLIANCEIQ_AZURE_COMPLIANT_VM_ID",
    "COMPLIANCEIQ_AZURE_NONCOMPLIANT_VM_ID",
    "COMPLIANCEIQ_AZURE_COMPLIANT_KEY_VAULT_ID",
    "COMPLIANCEIQ_AZURE_NONCOMPLIANT_KEY_VAULT_ID",
)


def pytest_collection_modifyitems(config, items):
    if os.environ.get(_GATE_ENV_VAR):
        return

    skip_marker = pytest.mark.skip(
        reason=(
            f"Azure integration tests are opt-in — set {_GATE_ENV_VAR}=1 "
            "(and the terraform-output env vars documented in "
            "tests/integration/azure/conftest.py) after deploying "
            "terraform/azure/environments/test. See "
            "docs/architecture/phase-3-azure.md."
        )
    )
    for item in items:
        if "tests/integration/azure" in str(item.fspath).replace("\\", "/"):
            item.add_marker(skip_marker)


@pytest.fixture(scope="session")
def terraform_outputs() -> dict:
    missing = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
    if missing:
        pytest.fail(
            f"{_GATE_ENV_VAR} is set, but these terraform-output env vars are "
            f"missing: {', '.join(missing)}. See tests/integration/azure/conftest.py."
        )
    return {name: os.environ[name] for name in REQUIRED_ENV_VARS}
