"""``AzureCollector`` — the concrete ``BaseCollector`` adapter for Azure.

The Azure sibling of ``infrastructure.cloud.aws.collector.AwsCollector``,
satisfying the SAME Phase 2 port (``application/scanning/collector.py``)
with no modification to that port and no change to ``AwsCollector``.
This is the whole multi-cloud story in one class: because both adapters
produce ``NormalizedResource``s, everything downstream — the
ResourceGraph, the rule DSL, ``EvaluateRules``, ``Finding``, the
conformance framework — is provider-agnostic and needed zero Azure
changes.

    AWS Collectors ─────┐
                        ├──> NormalizedResource ──> ResourceGraph
    Azure Collectors ───┘                              ──> Rule Engine
                                                            ──> Findings

Failure isolation matches ``AwsCollector`` exactly: one failing service
(most often a missing RBAC role) never prevents the rest of the
subscription from being scanned, but if EVERY sub-collector fails,
that's a systemic problem (credentials, network, subscription-wide
policy) and is raised rather than silently returning an empty result
indistinguishable from "this subscription genuinely has nothing".

Tenant identity is never derived from the Azure subscription or the
Azure AD tenant — it is supplied by the caller and threaded through to
every collected resource unchanged (blueprint Phase 3 brief §8).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable

from application.scanning.collector import BaseCollector
from domain.resources.models import NormalizedResource
from domain.shared.identifiers import TenantId
from infrastructure.cloud.azure.errors import AzureCollectionError, AzureError
from infrastructure.cloud.azure.resource_collectors.authorization import (
    RoleAssignmentCollector,
    RoleDefinitionCollector,
)
from infrastructure.cloud.azure.resource_collectors.base import AzureResourceCollector
from infrastructure.cloud.azure.resource_collectors.compute import VirtualMachineCollector
from infrastructure.cloud.azure.resource_collectors.keyvault import KeyVaultCollector
from infrastructure.cloud.azure.resource_collectors.monitor import ActivityLogSettingCollector
from infrastructure.cloud.azure.resource_collectors.network import NetworkSecurityGroupCollector
from infrastructure.cloud.azure.resource_collectors.storage import StorageAccountCollector
from infrastructure.cloud.azure.session import AzureClients

logger = logging.getLogger(__name__)


class AzureCollector(BaseCollector):
    """Collects normalized resources from one Azure subscription."""

    def __init__(
        self,
        *,
        clients: AzureClients,
        tenant_id: TenantId,
        clock: Callable[[], datetime] | None = None,
        sub_collectors: tuple[AzureResourceCollector, ...] | None = None,
    ) -> None:
        clock = clock or (lambda: datetime.now(timezone.utc))
        if sub_collectors is not None:
            self._sub_collectors = sub_collectors
        else:
            # The subscription id is the Azure account boundary and is
            # always known from the client bundle — no equivalent of
            # AWS's sts:GetCallerIdentity round trip is needed.
            account_id = clients.subscription_id
            self._sub_collectors = (
                StorageAccountCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
                NetworkSecurityGroupCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
                VirtualMachineCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
                KeyVaultCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
                ActivityLogSettingCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
                # RBAC (STEP 8C). Registered here rather than only being
                # written: an unregistered collector is dead in
                # production while every one of its own unit tests
                # passes — the defect that left `IamRoleCollector`
                # inert on the AWS side. A test now asserts this tuple.
                RoleDefinitionCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
                RoleAssignmentCollector(clients=clients, tenant_id=tenant_id, clock=clock, account_id=account_id),
            )

    def collect(self) -> tuple[NormalizedResource, ...]:
        resources: list[NormalizedResource] = []
        failures: list[tuple[str, AzureError]] = []

        for sub_collector in self._sub_collectors:
            try:
                resources.extend(sub_collector.collect())
            except AzureError as exc:
                logger.warning("failed to collect %s: %s", sub_collector.resource_type, exc)
                failures.append((sub_collector.resource_type, exc))

        if failures and len(failures) == len(self._sub_collectors):
            summary = "; ".join(f"{name}: {exc}" for name, exc in failures)
            raise AzureCollectionError(f"all Azure resource collection failed: {summary}") from failures[0][1]

        return tuple(resources)
