"""How to obtain Azure credentials — never the secrets themselves.

Mirrors ``infrastructure.cloud.aws.credentials.AwsCredentialConfig``'s
central rule exactly: this config object is a STRATEGY POINTER, never a
secret. There is deliberately no ``client_secret``, ``password``, or
``certificate`` field, so nothing in this codebase can accidentally
log, serialize, or commit an Azure credential that was never stored
here in the first place.

Authentication goes through ``azure.identity.DefaultAzureCredential``,
which resolves in its own documented order (environment variables, a
workload/managed identity, Azure CLI login, and so on) — the direct
analogue of boto3's default credential chain that
``AwsSessionFactory`` relies on.

``subscription_id`` is the Azure equivalent of the AWS account
boundary: every management-plane client is scoped to exactly one
subscription, and it is what populates ``NormalizedResource.account_id``
so multi-subscription scans stay collision-safe.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AzureCredentialConfig:
    """Configuration for how to obtain Azure clients — a strategy
    pointer, never a secret.

    ``tenant_id`` here is the AZURE AD tenant (a cloud-provider
    concept), which is emphatically NOT ComplianceIQ's own
    ``domain.shared.identifiers.TenantId`` (a customer of this
    platform). The two are never conflated: ComplianceIQ's tenant is
    always supplied by the caller, exactly as on the AWS side
    (blueprint Phase 3 brief §8 — the cloud account must never itself
    be treated as the tenant).
    """

    subscription_id: str
    tenant_id: str | None = None
    resource_group: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.subscription_id, str) or not self.subscription_id.strip():
            raise ValueError("subscription_id must be a non-blank string")
        if self.tenant_id is not None and not self.tenant_id.strip():
            raise ValueError("tenant_id must be None or a non-blank string")
        if self.resource_group is not None and not self.resource_group.strip():
            raise ValueError("resource_group must be None or a non-blank string")
