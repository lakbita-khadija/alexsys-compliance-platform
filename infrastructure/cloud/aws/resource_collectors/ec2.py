"""EC2 instance collection (blueprint §24 roadmap: Phase 3 completes
the AWS adapter with EC2, among others)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws import instance_profiles
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.ec2 import normalize_ec2_instance
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector
from infrastructure.cloud.resilience import CollectionStats, RetryPolicy


class Ec2Collector(AwsResourceCollector):
    """Collects every EC2 instance via boto3's ``describe_instances``
    paginator. AWS nests instances two levels deep
    (``Reservations -> Instances``) — this flattens that structure.
    """

    resource_type = "EC2 instances"

    def __init__(
        self,
        *,
        session,
        tenant_id,
        clock,
        account_id: str | None = None,
        retry_policy: RetryPolicy | None = None,
        stats: CollectionStats | None = None,
    ) -> None:
        super().__init__(
            session=session, tenant_id=tenant_id, clock=clock, account_id=account_id
        )
        self._retry_policy = retry_policy or RetryPolicy()
        self.stats = stats if stats is not None else CollectionStats()

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("ec2")
        # IAM is global; one client, reused for every instance profile
        # lookup rather than one per instance.
        iam_client = self._session.client("iam")
        try:
            return self._collect(client, iam_client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting EC2 instances")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client, iam_client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        region = self._session.region_name
        instances = [
            instance
            for page in client.get_paginator("describe_instances").paginate()
            for reservation in page.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
        return tuple(
            self._normalize(client, iam_client, instance, region, collected_at)
            for instance in instances
        )

    def _normalize(
        self, client, iam_client, instance: dict, region: str, collected_at
    ) -> NormalizedResource:
        tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
        security_group_ids = tuple(sg["GroupId"] for sg in instance.get("SecurityGroups", []))
        profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")

        # Resolves the profile to the role it actually holds. Never
        # raises: every failure is classified and returned, so one
        # unresolvable profile costs one edge rather than the instance.
        resolution = instance_profiles.resolve(
            iam_client,
            profile_arn,
            own_account_id=self._account_id,
            retry_policy=self._retry_policy,
            stats=self.stats,
        )
        return normalize_ec2_instance(
            instance_id=instance["InstanceId"],
            state=instance.get("State", {}).get("Name", "unknown"),
            region=region,
            vpc_id=instance.get("VpcId"),
            subnet_id=instance.get("SubnetId"),
            security_group_ids=security_group_ids,
            public_ip=instance.get("PublicIpAddress"),
            instance_profile_arn=profile_arn,
            instance_profile_resolution=resolution,
            imds_v2_required=instance.get("MetadataOptions", {}).get("HttpTokens") == "required",
            root_volume_encrypted=self._root_volume_encrypted(client, instance),
            tags=tags,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    @staticmethod
    def _root_volume_encrypted(client, instance: dict) -> bool | None:
        root_device_name = instance.get("RootDeviceName")
        volume_id = next(
            (
                mapping["Ebs"]["VolumeId"]
                for mapping in instance.get("BlockDeviceMappings", [])
                if mapping.get("DeviceName") == root_device_name and "Ebs" in mapping
            ),
            None,
        )
        if volume_id is None:
            return None
        volumes = client.describe_volumes(VolumeIds=[volume_id]).get("Volumes", [])
        if not volumes:
            return None
        return volumes[0].get("Encrypted", False)
