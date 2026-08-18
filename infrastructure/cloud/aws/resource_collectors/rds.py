"""RDS DB instance collection (STEP 8B).

The first collector in this codebase to use the `rds` client. Otherwise
it follows the established per-service pattern exactly: the same base
class, the same paginator use, the same `translate_client_error` →
`AwsCollectionError` wrapping, so `AwsCollector.collect()` isolates a
failure here the way it isolates every other.

Scope is DB **instances**. Clusters, snapshots and parameter groups are
deliberately out — `docs/audits/aws-rds-current-state.md` §2 records
what each omission costs, and the public-snapshot gap is called out
there as the most significant.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.rds import normalize_rds_instance
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector


class RdsInstanceCollector(AwsResourceCollector):
    """Collects every RDS DB instance in the session's region."""

    resource_type = "RDS instances"

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("rds")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting RDS instances")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        region = self._session.region_name
        instances = [
            instance
            for page in client.get_paginator("describe_db_instances").paginate()
            for instance in page.get("DBInstances", [])
        ]
        return tuple(
            normalize_rds_instance(
                instance=instance,
                region=region,
                tenant_id=self._tenant_id,
                collected_at=collected_at,
                account_id=self._account_id,
            )
            for instance in instances
        )


__all__ = ["RdsInstanceCollector"]
