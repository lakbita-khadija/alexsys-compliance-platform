"""Shared shape for every AWS per-service resource collector.

Not a port (``BaseCollector``, the Application-level port, is already
defined in ``application/scanning/collector.py``) — this is an internal
Infrastructure organizational detail shared by all six sub-collectors,
which otherwise would each duplicate the same constructor and the same
"how do I know when this resource was collected" clock handling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable

import boto3

from domain.resources.models import NormalizedResource
from domain.shared.identifiers import TenantId


class AwsResourceCollector(ABC):
    """Base for a single AWS service's resource collector (S3, IAM, ...)."""

    #: Human-readable name used in error messages (e.g. "S3 buckets").
    resource_type: str = "resources"

    def __init__(
        self,
        *,
        session: boto3.Session,
        tenant_id: TenantId,
        clock: Callable[[], datetime],
        account_id: str | None = None,
    ) -> None:
        self._session = session
        self._tenant_id = tenant_id
        self._clock = clock
        self._account_id = account_id

    @abstractmethod
    def collect(self) -> tuple[NormalizedResource, ...]:
        """Collect and normalize every resource this collector is
        responsible for. Raises a subclass of
        ``infrastructure.cloud.aws.errors.AwsError`` on failure —
        never a bare ``Exception`` or a boto3/botocore type.
        """
