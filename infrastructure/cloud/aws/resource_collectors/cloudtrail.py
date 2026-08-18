"""CloudTrail collection (blueprint §24 roadmap: Phase 3 completes the
AWS adapter with CloudTrail, among others — previously "mock only" per
the Phase 1 blueprint's Resource Coverage Matrix, §18).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.cloudtrail import normalize_cloudtrail_trail
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector


class CloudTrailCollector(AwsResourceCollector):
    """Collects every CloudTrail trail. ``DescribeTrails`` is not
    paginated (returns the full trail list in one call).
    """

    resource_type = "CloudTrail trails"

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("cloudtrail")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting CloudTrail trails")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        trails = client.describe_trails().get("trailList", [])
        return tuple(self._normalize(client, trail, collected_at) for trail in trails)

    def _normalize(self, client, trail: dict, collected_at) -> NormalizedResource:
        arn = trail["TrailARN"]
        is_logging = client.get_trail_status(Name=arn).get("IsLogging", False)
        return normalize_cloudtrail_trail(
            trail_arn=arn,
            name=trail.get("Name", ""),
            region=trail.get("HomeRegion") or self._session.region_name,
            is_multi_region_trail=trail.get("IsMultiRegionTrail", False),
            log_file_validation_enabled=trail.get("LogFileValidationEnabled", False),
            is_logging=is_logging,
            s3_bucket_name=trail.get("S3BucketName"),
            kms_key_id=trail.get("KmsKeyId"),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )
