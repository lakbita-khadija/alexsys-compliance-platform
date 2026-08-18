"""Security Group collection (blueprint §6: CURRENT)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.security_group import normalize_security_group
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector


class SecurityGroupCollector(AwsResourceCollector):
    """Collects every EC2 security group in the session's region via
    boto3's ``describe_security_groups`` paginator.
    """

    resource_type = "security groups"

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("ec2")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting security groups")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        region = self._session.region_name
        groups = [
            group
            for page in client.get_paginator("describe_security_groups").paginate()
            for group in page.get("SecurityGroups", [])
        ]
        return tuple(self._normalize(group, region, collected_at) for group in groups)

    def _normalize(self, group: dict, region: str, collected_at) -> NormalizedResource:
        tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
        return normalize_security_group(
            group_id=group["GroupId"],
            vpc_id=group.get("VpcId"),
            region=region,
            ingress_rules=group.get("IpPermissions", []),
            egress_rules=group.get("IpPermissionsEgress", []),
            tags=tags,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )
