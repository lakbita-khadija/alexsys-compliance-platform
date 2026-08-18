import json
from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from infrastructure.cloud.aws.errors import AwsCollectionError, AwsPermissionError
from infrastructure.cloud.aws.resource_collectors.s3 import S3Collector
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

PUBLIC_GRANT = {
    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
    "Permission": "READ",
}
PRIVATE_GRANT = {
    "Grantee": {"Type": "CanonicalUser", "ID": "owner-id"},
    "Permission": "FULL_CONTROL",
}


def not_found_error(operation: str, code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "not configured"}}, operation)


class FakeS3Client:
    """A minimal, hand-built fake of the subset of boto3's S3 client
    this collector uses. Each bucket's detail responses are supplied by
    the test as a dict keyed by bucket name.
    """

    def __init__(self, buckets, details):
        self._buckets = buckets
        self._details = details

    def list_buckets(self):
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_bucket_location(self, Bucket):
        return {"LocationConstraint": self._details[Bucket].get("region")}

    def get_bucket_encryption(self, Bucket):
        detail = self._details[Bucket]
        if not detail.get("encrypted"):
            raise not_found_error("GetBucketEncryption", "ServerSideEncryptionConfigurationNotFoundError")
        return {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}

    def get_public_access_block(self, Bucket):
        detail = self._details[Bucket]
        if not detail.get("public_access_block_enabled", True):
            raise not_found_error("GetPublicAccessBlock", "NoSuchPublicAccessBlockConfiguration")
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

    def get_bucket_acl(self, Bucket):
        grants = [PUBLIC_GRANT] if self._details[Bucket].get("public") else [PRIVATE_GRANT]
        return {"Grants": grants}

    def get_bucket_versioning(self, Bucket):
        if self._details[Bucket].get("versioning_enabled"):
            return {"Status": "Enabled"}
        return {}

    def get_bucket_logging(self, Bucket):
        if self._details[Bucket].get("logging_enabled"):
            return {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
        return {}

    def get_bucket_tagging(self, Bucket):
        tags = self._details[Bucket].get("tags")
        if not tags:
            raise not_found_error("GetBucketTagging", "NoSuchTagSet")
        return {"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]}

    def get_bucket_policy(self, Bucket):
        policy = self._details[Bucket].get("policy")
        if not policy:
            raise not_found_error("GetBucketPolicy", "NoSuchBucketPolicy")
        return {"Policy": json.dumps(policy)}


class FakeSession:
    def __init__(self, s3_client):
        self._s3_client = s3_client

    def client(self, service_name):
        assert service_name == "s3"
        return self._s3_client


def make_collector(buckets, details):
    session = FakeSession(FakeS3Client(buckets, details))
    return S3Collector(session=session, tenant_id=TENANT, clock=CLOCK)


class TestS3Collector:
    def test_collects_a_compliant_bucket(self) -> None:
        details = {
            "compliant-bucket": {
                "region": "eu-west-1",
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": True,
                "tags": {"env": "prod"},
            }
        }
        resources = make_collector(["compliant-bucket"], details).collect()
        assert len(resources) == 1
        resource = resources[0]
        assert resource.resource_id == ResourceId("compliant-bucket")
        assert resource.resource_type == "s3_bucket"
        assert resource.region == "eu-west-1"
        assert resource.attributes["encrypted"] is True
        assert resource.attributes["public"] is False
        assert resource.attributes["versioning_enabled"] is True
        assert resource.tags == {"env": "prod"}
        assert resource.tenant_id == TENANT
        assert resource.collected_at == CLOCK()

    def test_collects_a_noncompliant_bucket(self) -> None:
        details = {
            "public-bucket": {
                "region": "us-east-1",
                "encrypted": False,
                "public": True,
                "public_access_block_enabled": False,
                "versioning_enabled": False,
                "logging_enabled": False,
                "tags": {},
            }
        }
        resource = make_collector(["public-bucket"], details).collect()[0]
        assert resource.attributes["encrypted"] is False
        assert resource.attributes["public"] is True
        assert resource.attributes["public_access_block_enabled"] is False

    def test_us_east_1_location_constraint_none_is_normalized(self) -> None:
        details = {
            "bucket-1": {
                "region": None,
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": False,
                "logging_enabled": False,
                "tags": {},
            }
        }
        resource = make_collector(["bucket-1"], details).collect()[0]
        assert resource.region == "us-east-1"

    def test_bucket_with_no_tags_gets_empty_tags(self) -> None:
        details = {
            "bucket-1": {
                "region": "eu-west-1",
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": False,
                "logging_enabled": False,
                "tags": {},
            }
        }
        resource = make_collector(["bucket-1"], details).collect()[0]
        assert resource.tags == {}

    def test_empty_account_returns_empty_tuple(self) -> None:
        resources = make_collector([], {}).collect()
        assert resources == ()

    def test_multiple_buckets_are_all_collected(self) -> None:
        details = {
            f"bucket-{i}": {
                "region": "eu-west-1",
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": True,
                "tags": {},
            }
            for i in range(3)
        }
        resources = make_collector(list(details), details).collect()
        assert len(resources) == 3

    def test_permission_error_is_translated_and_wrapped(self) -> None:
        class DenyingClient(FakeS3Client):
            def list_buckets(self):
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListBuckets")

        session = FakeSession(DenyingClient([], {}))
        collector = S3Collector(session=session, tenant_id=TENANT, clock=CLOCK)
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsPermissionError)

    def test_collection_is_deterministic(self) -> None:
        details = {
            "bucket-1": {
                "region": "eu-west-1",
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": True,
                "tags": {"env": "prod"},
            }
        }
        first = make_collector(["bucket-1"], details).collect()
        second = make_collector(["bucket-1"], details).collect()
        assert first == second


class TestS3CollectorBucketPolicy:
    def _details(self, **overrides):
        base = {
            "region": "us-east-1",
            "encrypted": True,
            "public": False,
            "public_access_block_enabled": True,
            "versioning_enabled": True,
            "logging_enabled": True,
            "tags": {},
        }
        base.update(overrides)
        return {"bucket-1": base}

    def test_bucket_with_no_policy(self) -> None:
        resource = make_collector(["bucket-1"], self._details()).collect()[0]
        assert resource.attributes["has_bucket_policy"] is False
        assert resource.attributes["bucket_policy_allows_public_access"] is False

    def test_bucket_with_private_policy(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}]}
        resource = make_collector(["bucket-1"], self._details(policy=policy)).collect()[0]
        assert resource.attributes["has_bucket_policy"] is True
        assert resource.attributes["bucket_policy_allows_public_access"] is False

    def test_bucket_with_public_policy(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}
        resource = make_collector(["bucket-1"], self._details(policy=policy)).collect()[0]
        assert resource.attributes["has_bucket_policy"] is True
        assert resource.attributes["bucket_policy_allows_public_access"] is True


class TestS3CollectorAccountId:
    def test_account_id_is_threaded_into_resources(self) -> None:
        details = {
            "bucket-1": {
                "region": "us-east-1",
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": True,
                "tags": {},
            }
        }
        session = FakeSession(FakeS3Client(["bucket-1"], details))
        collector = S3Collector(session=session, tenant_id=TENANT, clock=CLOCK, account_id="123456789012")
        resource = collector.collect()[0]
        assert resource.account_id == "123456789012"

    def test_account_id_defaults_to_none(self) -> None:
        resource = make_collector(["bucket-1"], self._details_for_none()).collect()[0]
        assert resource.account_id is None

    @staticmethod
    def _details_for_none():
        return {
            "bucket-1": {
                "region": "us-east-1",
                "encrypted": True,
                "public": False,
                "public_access_block_enabled": True,
                "versioning_enabled": True,
                "logging_enabled": True,
                "tags": {},
            }
        }
