"""Shared shape for every Azure per-service resource collector.

The direct counterpart of
``infrastructure.cloud.aws.resource_collectors.base.AwsResourceCollector``,
and — like it — NOT a port: ``BaseCollector``
(``application/scanning/collector.py``) is the Application-level port,
and it is satisfied once, by ``AzureCollector``. This class is an
internal Infrastructure organizational detail shared by the Azure
sub-collectors, which would otherwise each duplicate the same
constructor and clock handling.

``account_id`` carries the Azure SUBSCRIPTION ID (the Azure analogue of
an AWS account id), so every collected resource is subscription-
qualified for the same multi-account collision-safety reason documented
in ``domain/resources/models.py``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable

from domain.resources.models import NormalizedResource
from domain.shared.identifiers import TenantId
from infrastructure.cloud.azure.session import AzureClients


class AzureResourceCollector(ABC):
    """Base for a single Azure service's resource collector."""

    #: Human-readable name used in error messages (e.g. "storage accounts").
    resource_type: str = "resources"

    def __init__(
        self,
        *,
        clients: AzureClients,
        tenant_id: TenantId,
        clock: Callable[[], datetime],
        account_id: str | None = None,
    ) -> None:
        self._clients = clients
        self._tenant_id = tenant_id
        self._clock = clock
        self._account_id = account_id or getattr(clients, "subscription_id", None)

    @abstractmethod
    def collect(self) -> tuple[NormalizedResource, ...]:
        """Collect and normalize every resource this collector is
        responsible for. Raises a subclass of
        ``infrastructure.cloud.azure.errors.AzureError`` on failure —
        never a bare ``Exception`` or an Azure SDK type.
        """
