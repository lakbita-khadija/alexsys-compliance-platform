"""S3 bucket collection (blueprint §6: CURRENT, one of the three
already-collected AWS resource types).
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from domain.resources.models import NormalizedResource
from infrastructure.cloud.aws.errors import AwsCollectionError, translate_client_error
from infrastructure.cloud.aws.normalizers.s3 import normalize_s3_bucket
from infrastructure.cloud.aws.policy_analysis import policy_allows_public_principal
from infrastructure.cloud.aws.resource_collectors.base import AwsResourceCollector

_PUBLIC_GROUP_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)


class S3Collector(AwsResourceCollector):
    """Collects every S3 bucket in the account (S3's ``ListBuckets`` API
    is not paginated).
    """

    resource_type = "S3 buckets"

    def collect(self) -> tuple[NormalizedResource, ...]:
        client = self._session.client("s3")
        try:
            return self._collect(client)
        except ClientError as exc:
            cause = translate_client_error(exc, context="collecting S3 buckets")
            raise AwsCollectionError(f"failed to collect {self.resource_type}") from cause

    def _collect(self, client) -> tuple[NormalizedResource, ...]:
        buckets = client.list_buckets().get("Buckets", [])
        collected_at = self._clock()
        return tuple(
            self._collect_one(client, bucket["Name"], collected_at) for bucket in buckets
        )

    def _collect_one(self, client, name: str, collected_at) -> NormalizedResource:
        policy_document = self._bucket_policy(client, name)
        return normalize_s3_bucket(
            name=name,
            region=self._region(client, name),
            encrypted=self._is_encrypted(client, name),
            public=self._is_public(client, name),
            public_access_block_enabled=self._is_public_access_blocked(client, name),
            versioning_enabled=self._is_versioning_enabled(client, name),
            logging_enabled=self._is_logging_enabled(client, name),
            has_bucket_policy=policy_document is not None,
            bucket_policy_allows_public_access=policy_allows_public_principal(policy_document),
            tags=self._tags(client, name),
            tenant_id=self._tenant_id,
            collected_at=collected_at,
            account_id=self._account_id,
        )

    @staticmethod
    def _bucket_policy(client, name: str) -> dict | None:
        try:
            document = client.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError as exc:
            if _error_code(exc) == "NoSuchBucketPolicy":
                return None
            raise
        return json.loads(document) if isinstance(document, str) else document

    @staticmethod
    def _region(client, name: str) -> str:
        # AWS returns LocationConstraint=None (or the key absent) for
        # buckets in us-east-1 — the one region with no explicit code.
        location = client.get_bucket_location(Bucket=name).get("LocationConstraint")
        return location or "us-east-1"

    @staticmethod
    def _is_encrypted(client, name: str) -> bool:
        try:
            client.get_bucket_encryption(Bucket=name)
            return True
        except ClientError as exc:
            if _error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
                return False
            raise

    @staticmethod
    def _is_public_access_blocked(client, name: str) -> bool:
        try:
            config = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if _error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return False
            raise
        return all(
            config.get(flag, False)
            for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        )

    @staticmethod
    def _is_public(client, name: str) -> bool:
        grants = client.get_bucket_acl(Bucket=name).get("Grants", [])
        return any(
            grant.get("Grantee", {}).get("Type") == "Group"
            and grant.get("Grantee", {}).get("URI") in _PUBLIC_GROUP_URIS
            for grant in grants
        )

    @staticmethod
    def _is_versioning_enabled(client, name: str) -> bool:
        return client.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"

    @staticmethod
    def _is_logging_enabled(client, name: str) -> bool:
        return "LoggingEnabled" in client.get_bucket_logging(Bucket=name)

    @staticmethod
    def _tags(client, name: str) -> dict[str, str]:
        try:
            tag_set = client.get_bucket_tagging(Bucket=name)["TagSet"]
        except ClientError as exc:
            if _error_code(exc) == "NoSuchTagSet":
                return {}
            raise
        return {tag["Key"]: tag["Value"] for tag in tag_set}


def _error_code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")
