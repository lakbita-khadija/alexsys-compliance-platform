"""``AwsCollector`` — the concrete ``BaseCollector`` adapter for AWS.

Satisfies Phase 2's ``BaseCollector`` port (``application/scanning/collector.py``)
without any modification to that port — this class is a pure
implementation detail Phase 2 already anticipated. Orchestrates the
per-service sub-collectors (six originally; fourteen since the STEP 8A
network foundation and STEP 8B RDS), isolating each one's failure so a
single
denied permission (e.g. no KMS access) never prevents the rest of the
account from being scanned (blueprint §6's ``_safe()`` pattern). If
*every* sub-collector fails, that's treated as a systemic problem
(credentials, network, account-wide policy) and raised, rather than
silently returning an empty result that would look identical to "this
AWS account genuinely has nothing."

Tenant identity is never derived from the AWS account — it is supplied
by the caller (blueprint Phase 3 brief §8) and threaded through to
every collected resource unchanged.

``account_id`` (Phase 3B, multi-account collision safety — see
``domain/findings/models.py`` and ``domain/resources/models.py``) is
resolved once here, via ``sts:GetCallerIdentity``, and threaded into
every sub-collector so it ends up on every ``NormalizedResource``. STS
failure is treated as non-fatal: ``account_id`` is an additive field
(nothing in Phase 1/2 requires it), so a denied ``sts:GetCallerIdentity``
degrades to ``account_id=None`` on every resource rather than aborting
the whole scan — the one exception being ``IamAccountCollector``, which
has no resource identity without an account id and simply collects
nothing in that case (see its own docstring).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Callable

import boto3

from application.scanning.collector import BaseCollector
from domain.resources.models import NormalizedResource
from domain.shared.identifiers import TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError, AwsError
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector
from infrastructure.cloud.aws.resource_collectors.cloudtrail import CloudTrailCollector
from infrastructure.cloud.aws.resource_collectors.ec2 import Ec2Collector
from infrastructure.cloud.aws.resource_collectors.iam import IamAccountCollector, IamCollector
from infrastructure.cloud.aws.resource_collectors.iam_roles import IamRoleCollector
from infrastructure.cloud.aws.resource_collectors.kms import KmsCollector
from infrastructure.cloud.aws.resource_collectors.network import (
    InternetGatewayCollector,
    NetworkAclCollector,
    RouteTableCollector,
    SubnetCollector,
    VpcCollector,
)
from infrastructure.cloud.aws.resource_collectors.rds import RdsInstanceCollector
from infrastructure.cloud.aws.resource_collectors.s3 import S3Collector
from infrastructure.cloud.aws.resource_collectors.security_groups import SecurityGroupCollector

logger = logging.getLogger(__name__)


def _resolve_account_id(session: boto3.Session) -> str | None:
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except Exception as exc:  # noqa: BLE001 - see module docstring: non-fatal by design
        logger.warning("failed to resolve AWS account id via STS: %s", exc)
        return None


class AwsCollector(BaseCollector):
    """Collects normalized resources from one AWS account/session."""

    def __init__(
        self,
        *,
        session: boto3.Session,
        tenant_id: TenantId,
        clock: Callable[[], datetime] | None = None,
        sub_collectors: tuple[AwsResourceCollector, ...] | None = None,
    ) -> None:
        clock = clock or (lambda: datetime.now(timezone.utc))
        if sub_collectors is not None:
            self._sub_collectors = sub_collectors
        else:
            account_id = _resolve_account_id(session)
            self._sub_collectors = (
                S3Collector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                IamCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                IamAccountCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                # Registered late (audit: post-study-guide-current-state.md §2).
                # Its absence meant no `iam_role` was collected in any real
                # scan, so the ONLY producer of `PUBLICLY_EXPOSED` never ran:
                # attack path scenario `public_identity_with_privilege` could
                # not fire in production, and the semantic IAM policy engine
                # was unreachable. Every unit test passed throughout, because
                # nothing exercised this default tuple.
                IamRoleCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                Ec2Collector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                SecurityGroupCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                CloudTrailCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                KmsCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                # Network topology (STEP 8A). Registered here at the same
                # time the collectors were written, deliberately: the
                # STEP 0 audit found IamRoleCollector fully implemented,
                # fully unit-tested and absent from this tuple, so it
                # never ran in production while every test passed. The
                # classification test derives the expected set from the
                # package, so an unregistered collector now fails.
                VpcCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                SubnetCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                RouteTableCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                InternetGatewayCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                NetworkAclCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
                # Managed databases (STEP 8B). The first collector to
                # use the `rds` client.
                RdsInstanceCollector(session=session, tenant_id=tenant_id, clock=clock, account_id=account_id),
            )

    def collect(self) -> tuple[NormalizedResource, ...]:
        resources: list[NormalizedResource] = []
        failures: list[tuple[str, AwsError]] = []

        for sub_collector in self._sub_collectors:
            try:
                resources.extend(sub_collector.collect())
            except AwsError as exc:
                logger.warning("failed to collect %s: %s", sub_collector.resource_type, exc)
                failures.append((sub_collector.resource_type, exc))

        if failures and len(failures) == len(self._sub_collectors):
            summary = "; ".join(f"{name}: {exc}" for name, exc in failures)
            raise AwsCollectionError(f"all AWS resource collection failed: {summary}") from failures[0][1]

        return tuple(resources)
