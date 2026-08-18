import json
from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError, AwsPermissionError
from infrastructure.cloud.aws.resource_collectors.kms import KmsCollector

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class FakeKmsClient:
    def __init__(self, key_pages, metadata_by_id, rotation_by_id=None, policy_by_id=None):
        self._key_pages = key_pages
        self._metadata_by_id = metadata_by_id
        self._rotation_by_id = rotation_by_id or {}
        self._policy_by_id = policy_by_id or {}

    def get_paginator(self, op_name):
        assert op_name == "list_keys"
        return FakePaginator(self._key_pages)

    def describe_key(self, KeyId):
        return {"KeyMetadata": self._metadata_by_id[KeyId]}

    def get_key_rotation_status(self, KeyId):
        return {"KeyRotationEnabled": self._rotation_by_id.get(KeyId, False)}

    def get_key_policy(self, KeyId, PolicyName):
        assert PolicyName == "default"
        policy = self._policy_by_id.get(KeyId)
        if policy is None:
            return {"Policy": None}
        return {"Policy": json.dumps(policy)}


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "kms"
        return self._client


def key_metadata(key_id, arn=None, state="Enabled", manager="CUSTOMER"):
    return {
        "KeyId": key_id,
        "Arn": arn or f"arn:aws:kms:us-east-1:123:key/{key_id}",
        "KeyState": state,
        "KeyManager": manager,
    }


def make_collector(key_pages, metadata_by_id, rotation_by_id=None, policy_by_id=None, account_id=None):
    client = FakeKmsClient(key_pages, metadata_by_id, rotation_by_id, policy_by_id)
    return KmsCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id=account_id)


class TestKmsCollectorBasics:
    def test_collects_a_key_with_rotation_enabled(self) -> None:
        metadata = {"key-1": key_metadata("key-1")}
        resources = make_collector([{"Keys": [{"KeyId": "key-1"}]}], metadata, {"key-1": True}).collect()
        resource = resources[0]
        assert resource.resource_id == ResourceId("arn:aws:kms:us-east-1:123:key/key-1")
        assert resource.resource_type == "kms_key"
        assert resource.attributes["key_state"] == "Enabled"
        assert resource.attributes["rotation_enabled"] is True

    def test_collects_a_key_with_rotation_disabled(self) -> None:
        metadata = {"key-1": key_metadata("key-1")}
        resources = make_collector([{"Keys": [{"KeyId": "key-1"}]}], metadata, {"key-1": False}).collect()
        assert resources[0].attributes["rotation_enabled"] is False

    def test_aws_managed_key_has_no_rotation_status_call(self) -> None:
        metadata = {"key-1": key_metadata("key-1", manager="AWS")}
        resources = make_collector([{"Keys": [{"KeyId": "key-1"}]}], metadata).collect()
        assert resources[0].attributes["rotation_enabled"] is None
        assert resources[0].attributes["key_manager"] == "AWS"

    def test_no_keys_returns_empty_tuple(self) -> None:
        resources = make_collector([{"Keys": []}], {}).collect()
        assert resources == ()


class TestKmsCollectorPagination:
    def test_keys_are_combined_across_multiple_pages(self) -> None:
        pages = [{"Keys": [{"KeyId": "key-1"}]}, {"Keys": [{"KeyId": "key-2"}]}]
        metadata = {"key-1": key_metadata("key-1"), "key-2": key_metadata("key-2")}
        resources = make_collector(pages, metadata, {"key-1": True, "key-2": True}).collect()
        assert len(resources) == 2


class TestKmsCollectorErrors:
    def test_permission_error_is_translated_and_wrapped(self) -> None:
        class DenyingClient(FakeKmsClient):
            def get_paginator(self, op_name):
                class _Raising:
                    def paginate(self):
                        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "ListKeys")

                return _Raising()

        collector = KmsCollector(session=FakeSession(DenyingClient([], {})), tenant_id=TENANT, clock=CLOCK)
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsPermissionError)


class TestKmsCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        pages = [{"Keys": [{"KeyId": "key-1"}]}]
        metadata = {"key-1": key_metadata("key-1")}
        first = make_collector(pages, metadata, {"key-1": True}).collect()
        second = make_collector(pages, metadata, {"key-1": True}).collect()
        assert first == second


class TestKmsCollectorKeyPolicy:
    def test_key_with_no_policy_is_not_public(self) -> None:
        pages = [{"Keys": [{"KeyId": "key-1"}]}]
        metadata = {"key-1": key_metadata("key-1")}
        resource = make_collector(pages, metadata, {"key-1": True}).collect()[0]
        assert resource.attributes["key_policy_allows_public_access"] is False

    def test_key_with_scoped_policy_is_not_public(self) -> None:
        pages = [{"Keys": [{"KeyId": "key-1"}]}]
        metadata = {"key-1": key_metadata("key-1")}
        policy = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}}]}
        resource = make_collector(pages, metadata, {"key-1": True}, {"key-1": policy}).collect()[0]
        assert resource.attributes["key_policy_allows_public_access"] is False

    def test_key_with_public_policy_is_public(self) -> None:
        pages = [{"Keys": [{"KeyId": "key-1"}]}]
        metadata = {"key-1": key_metadata("key-1")}
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt"}]}
        resource = make_collector(pages, metadata, {"key-1": True}, {"key-1": policy}).collect()[0]
        assert resource.attributes["key_policy_allows_public_access"] is True


class TestKmsCollectorAccountId:
    def test_account_id_is_threaded_into_resources(self) -> None:
        pages = [{"Keys": [{"KeyId": "key-1"}]}]
        metadata = {"key-1": key_metadata("key-1")}
        resource = make_collector(pages, metadata, {"key-1": True}, account_id="123456789012").collect()[0]
        assert resource.account_id == "123456789012"
