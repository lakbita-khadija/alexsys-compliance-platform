"""KMS key collection (blueprint §24 roadmap: Phase 3 completes the
AWS adapter with KMS, among others).
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.kms import normalize_kms_key
from infrastructure.cloud.aws.policy_analysis import policy_allows_public_principal
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector

_AWS_MANAGED = "AWS"


class KmsCollector(AwsResourceCollector):
    """Collects every KMS key via boto3's ``list_keys`` paginator.
    Rotation status is only queried for customer-managed keys — AWS
    doesn't support (and errors on) that query for AWS-managed keys.
    """

    resource_type = "KMS keys"

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("kms")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting KMS keys")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        collected_at = self._clock()
        region = self._session.region_name
        key_ids = [
            key["KeyId"]
            for page in client.get_paginator("list_keys").paginate()
            for key in page.get("Keys", [])
        ]
        return tuple(self._normalize(client, key_id, region, collected_at) for key_id in key_ids)

    def _normalize(self, client, key_id: str, region: str, collected_at) -> NormalizedResource:
        metadata = client.describe_key(KeyId=key_id)["KeyMetadata"]
        key_manager = metadata.get("KeyManager", _AWS_MANAGED)

        rotation_enabled = None
        if key_manager != _AWS_MANAGED:
            rotation_enabled = client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled", False)

        return normalize_kms_key(
            key_arn=metadata["Arn"],
            key_state=metadata.get("KeyState", "Unknown"),
            key_manager=key_manager,
            rotation_enabled=rotation_enabled,
            key_policy_allows_public_access=policy_allows_public_principal(self._key_policy(client, key_id)),
            region=region,
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    @staticmethod
    def _key_policy(client, key_id: str) -> dict | None:
        document = client.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy")
        if not document:
            return None
        return json.loads(document) if isinstance(document, str) else document
