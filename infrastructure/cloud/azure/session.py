"""``AzureSessionFactory`` — the one place Azure management clients are
constructed.

The direct counterpart of ``infrastructure.cloud.aws.session.AwsSessionFactory``,
and it exists for the same reason: isolating client construction in one
small class is what makes every collector unit-testable without Azure
credentials. Tests construct a collector with fake client objects and
never go through this factory at all; production code goes through it
exactly once per scan.

Azure differs from AWS in one structural way that shapes this class:
boto3 has a single ``Session`` that mints per-service clients, whereas
each Azure management SDK is its own package with its own client class
(``StorageManagementClient``, ``NetworkManagementClient``, ...). So
instead of returning one session object, this factory returns an
``AzureClients`` bundle holding one client per service the collectors
need. The Azure SDK imports are deferred into ``create()`` so that
merely importing this module (as the collectors' own unit tests do)
never requires the SDK to be installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from infrastructure.cloud.azure.credentials import AzureCredentialConfig
from infrastructure.cloud.azure.errors import translate_azure_error


@dataclass(frozen=True, slots=True)
class AzureClients:
    """One management client per Azure service ComplianceIQ collects.

    Typed as ``Any`` deliberately: these are concrete Azure SDK client
    classes, and annotating them properly would force an unconditional
    SDK import at module scope, which is exactly what the deferred
    import in ``AzureSessionFactory.create`` avoids. The collectors
    only ever call documented methods on them, and every collector is
    unit-tested against a hand-built fake of that same surface.
    """

    subscription_id: str
    storage: Any
    network: Any
    compute: Any
    keyvault: Any
    monitor: Any
    #: `azure-mgmt-authorization` — RBAC role assignments and role
    #: definitions (STEP 8C). Defaulted so every existing construction
    #: site, including the collectors' own fakes, is unchanged; the
    #: RBAC collectors fail through the normal Azure error taxonomy if
    #: it is ever absent in production.
    authorization: Any = None
    #: The credential the clients were built from (STEP 6.5).
    #:
    #: Exposed so `AzureIdentityProvider` can ask it for a token and read
    #: which Entra directory actually authenticated. Before this, the
    #: credential was constructed and immediately became unreachable, so
    #: nothing could verify what it had resolved to — the subscription id
    #: from config was the only "identity" available, and comparing
    #: configuration against itself proves nothing.
    #:
    #: This holds a credential OBJECT, not credential material: it knows
    #: how to mint tokens, and carries no secret this codebase ever sees.
    credential: Any = None


class AzureSessionFactory:
    """Builds an ``AzureClients`` bundle from an ``AzureCredentialConfig``.

    Never constructs a credential from a raw client secret — only
    ``DefaultAzureCredential``, which resolves through Azure's own
    documented chain (environment, managed identity, Azure CLI, ...).
    """

    def create(self, config: AzureCredentialConfig) -> AzureClients:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.keyvault import KeyVaultManagementClient
            from azure.mgmt.monitor import MonitorManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.storage import StorageManagementClient
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise translate_azure_error(exc, context="importing the Azure SDK") from exc

        # `interactive_browser_tenant_id` scopes ONLY the interactive
        # browser link in the chain. Under environment credentials,
        # managed identity or workload identity — every mode a deployed
        # scanner actually uses — it has no effect whatsoever.
        #
        # It is kept because it genuinely helps the local `az login`
        # path, and it is NOT the tenant control. Constraining
        # `DefaultAzureCredential`'s whole chain to a directory is not
        # something the class supports; the directory is therefore
        # VERIFIED after the fact by `AzureIdentityProvider`, which reads
        # the `tid` claim of a real token, and enforced by
        # `verify_cloud_identity` against the tenant's binding.
        #
        # Passing this and calling it tenant validation was the defect
        # `cloud-auth-readiness.md` §3.2 recorded. The parameter stays;
        # the false claim does not.
        credential = (
            DefaultAzureCredential(interactive_browser_tenant_id=config.tenant_id)
            if config.tenant_id
            else DefaultAzureCredential()
        )

        subscription_id = config.subscription_id
        return AzureClients(
            subscription_id=subscription_id,
            storage=StorageManagementClient(credential, subscription_id),
            network=NetworkManagementClient(credential, subscription_id),
            compute=ComputeManagementClient(credential, subscription_id),
            keyvault=KeyVaultManagementClient(credential, subscription_id),
            monitor=MonitorManagementClient(credential, subscription_id),
            authorization=AuthorizationManagementClient(credential, subscription_id),
            credential=credential,
        )
