from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError, AwsServiceError
from infrastructure.cloud.aws.resource_collectors.cloudtrail import CloudTrailCollector

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731


class FakeCloudTrailClient:
    def __init__(self, trails, logging_status_by_arn=None):
        self._trails = trails
        self._logging_status_by_arn = logging_status_by_arn or {}

    def describe_trails(self):
        return {"trailList": self._trails}

    def get_trail_status(self, Name):
        return {"IsLogging": self._logging_status_by_arn.get(Name, False)}


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "cloudtrail"
        return self._client


def trail(arn, name="trail-1", multi_region=True, validation=True, s3_bucket="log-bucket", kms_key_id=None, home_region="us-east-1"):
    return {
        "TrailARN": arn,
        "Name": name,
        "IsMultiRegionTrail": multi_region,
        "LogFileValidationEnabled": validation,
        "S3BucketName": s3_bucket,
        "KmsKeyId": kms_key_id,
        "HomeRegion": home_region,
    }


def make_collector(trails, logging_status_by_arn=None):
    client = FakeCloudTrailClient(trails, logging_status_by_arn)
    return CloudTrailCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK)


class TestCloudTrailCollectorBasics:
    def test_collects_a_compliant_trail(self) -> None:
        t = trail("arn:aws:cloudtrail:us-east-1:123:trail/trail-1")
        resources = make_collector([t], {t["TrailARN"]: True}).collect()
        resource = resources[0]
        assert resource.resource_id == ResourceId("arn:aws:cloudtrail:us-east-1:123:trail/trail-1")
        assert resource.resource_type == "cloudtrail"
        assert resource.attributes["is_multi_region_trail"] is True
        assert resource.attributes["log_file_validation_enabled"] is True
        assert resource.attributes["is_logging"] is True
        assert resource.attributes["s3_bucket_name"] == "log-bucket"

    def test_collects_a_noncompliant_single_region_trail(self) -> None:
        t = trail("arn:1", multi_region=False, validation=False)
        resources = make_collector([t], {"arn:1": False}).collect()
        resource = resources[0]
        assert resource.attributes["is_multi_region_trail"] is False
        assert resource.attributes["log_file_validation_enabled"] is False
        assert resource.attributes["is_logging"] is False

    def test_kms_key_id_is_captured_when_present(self) -> None:
        t = trail("arn:1", kms_key_id="arn:aws:kms:us-east-1:123:key/abc")
        resource = make_collector([t], {"arn:1": True}).collect()[0]
        assert resource.attributes["kms_key_id"] == "arn:aws:kms:us-east-1:123:key/abc"

    def test_kms_key_id_is_none_when_trail_is_unencrypted(self) -> None:
        t = trail("arn:1", kms_key_id=None)
        resource = make_collector([t], {"arn:1": True}).collect()[0]
        assert resource.attributes["kms_key_id"] is None

    def test_region_comes_from_home_region(self) -> None:
        t = trail("arn:1", home_region="eu-west-1")
        resource = make_collector([t], {"arn:1": True}).collect()[0]
        assert resource.region == "eu-west-1"

    def test_no_trails_returns_empty_tuple(self) -> None:
        resources = make_collector([]).collect()
        assert resources == ()


class TestCloudTrailCollectorErrors:
    def test_service_error_is_translated_and_wrapped(self) -> None:
        class FailingClient(FakeCloudTrailClient):
            def describe_trails(self):
                raise ClientError({"Error": {"Code": "InternalFailure", "Message": "oops"}}, "DescribeTrails")

        collector = CloudTrailCollector(session=FakeSession(FailingClient([])), tenant_id=TENANT, clock=CLOCK)
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsServiceError)


class TestCloudTrailCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        t = trail("arn:1")
        first = make_collector([t], {"arn:1": True}).collect()
        second = make_collector([t], {"arn:1": True}).collect()
        assert first == second


class TestCloudTrailAccessesS3Relationship:
    def test_trail_with_bucket_gets_accesses_relationship(self) -> None:
        t = trail("arn:1", s3_bucket="log-bucket")
        resource = make_collector([t], {"arn:1": True}).collect()[0]
        assert len(resource.relationships) == 1
        relationship = resource.relationships[0]
        assert relationship.relationship_type is RelationshipType.ACCESSES
        assert relationship.target_resource_id == ResourceId("log-bucket")

    def test_trail_with_no_bucket_has_no_relationships(self) -> None:
        t = trail("arn:1", s3_bucket=None)
        resource = make_collector([t], {"arn:1": True}).collect()[0]
        assert resource.relationships == ()


class TestCloudTrailCollectorAccountId:
    def test_account_id_is_threaded_into_resources(self) -> None:
        t = trail("arn:1")
        client = FakeCloudTrailClient([t], {"arn:1": True})
        collector = CloudTrailCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        resource = collector.collect()[0]
        assert resource.account_id == "123456789012"
