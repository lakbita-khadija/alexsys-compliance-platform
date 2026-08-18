from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.errors import AwsAuthenticationError, AwsCollectionError
from infrastructure.cloud.aws.resource_collectors.iam import IamAccountCollector, IamCollector

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

_ADMIN_DOCUMENT = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
_SCOPED_DOCUMENT = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return iter(self._pages)


class FakeIamClient:
    def __init__(
        self,
        user_pages,
        access_key_pages_by_user=None,
        policy_pages_by_user=None,
        mfa_by_user=None,
        policy_documents_by_arn=None,
    ):
        self._user_pages = user_pages
        self._access_key_pages_by_user = access_key_pages_by_user or {}
        self._policy_pages_by_user = policy_pages_by_user or {}
        self._mfa_by_user = mfa_by_user or {}
        self._policy_documents_by_arn = policy_documents_by_arn or {}

    def get_paginator(self, op_name):
        if op_name == "list_users":
            return FakePaginator(self._user_pages)
        if op_name == "list_access_keys":
            return _PerUserPaginator(self._access_key_pages_by_user)
        if op_name == "list_attached_user_policies":
            return _PerUserPaginator(self._policy_pages_by_user)
        raise NotImplementedError(op_name)

    def list_mfa_devices(self, UserName):
        return {"MFADevices": self._mfa_by_user.get(UserName, [])}

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        document = self._policy_documents_by_arn.get(PolicyArn, _SCOPED_DOCUMENT)
        return {"PolicyVersion": {"Document": document}}


class _PerUserPaginator:
    def __init__(self, pages_by_user):
        self._pages_by_user = pages_by_user

    def paginate(self, UserName):
        return iter(self._pages_by_user.get(UserName, []))


class FakeSession:
    def __init__(self, iam_client):
        self._iam_client = iam_client

    def client(self, service_name):
        assert service_name == "iam"
        return self._iam_client


def user(name, arn=None):
    return {"UserName": name, "Arn": arn or f"arn:aws:iam::123456789012:user/{name}"}


class TestIamCollectorBasics:
    def test_collects_a_single_user(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": [user("alice")]}])
        resources = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()
        assert len(resources) == 1
        resource = resources[0]
        assert resource.resource_id == ResourceId("arn:aws:iam::123456789012:user/alice")
        assert resource.resource_type == "iam_user"

    def test_iam_users_are_global_with_no_region(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": [user("alice")]}])
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.region is None

    def test_empty_account_returns_empty_tuple(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": []}])
        resources = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()
        assert resources == ()


class TestIamCollectorMfaAndKeys:
    def test_mfa_active_when_device_present(self) -> None:
        client = FakeIamClient(
            user_pages=[{"Users": [user("alice")]}],
            mfa_by_user={"alice": [{"SerialNumber": "arn:...:mfa/alice"}]},
        )
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["mfa_active"] is True

    def test_mfa_inactive_when_no_device(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": [user("bob")]}], mfa_by_user={})
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["mfa_active"] is False

    def test_access_key_counts(self) -> None:
        client = FakeIamClient(
            user_pages=[{"Users": [user("alice")]}],
            access_key_pages_by_user={
                "alice": [
                    {
                        "AccessKeyMetadata": [
                            {"AccessKeyId": "AKIA1", "Status": "Active"},
                            {"AccessKeyId": "AKIA2", "Status": "Inactive"},
                        ]
                    }
                ]
            },
        )
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["access_key_count"] == 2
        assert resource.attributes["active_access_key_count"] == 1

    def test_access_keys_are_combined_across_multiple_pages(self) -> None:
        client = FakeIamClient(
            user_pages=[{"Users": [user("alice")]}],
            access_key_pages_by_user={
                "alice": [
                    {"AccessKeyMetadata": [{"AccessKeyId": "AKIA1", "Status": "Active"}]},
                    {"AccessKeyMetadata": [{"AccessKeyId": "AKIA2", "Status": "Active"}]},
                ]
            },
        )
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["access_key_count"] == 2

    def test_attached_policy_names(self) -> None:
        client = FakeIamClient(
            user_pages=[{"Users": [user("alice")]}],
            policy_pages_by_user={
                "alice": [
                    {
                        "AttachedPolicies": [
                            {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
                        ]
                    }
                ]
            },
        )
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["attached_policy_names"] == ("AdministratorAccess",)


class TestIamCollectorFullAdminPolicy:
    def _client(self, document):
        return FakeIamClient(
            user_pages=[{"Users": [user("alice")]}],
            policy_pages_by_user={
                "alice": [{"AttachedPolicies": [{"PolicyName": "SomePolicy", "PolicyArn": "arn:policy/1"}]}]
            },
            policy_documents_by_arn={"arn:policy/1": document},
        )

    def test_admin_policy_sets_has_full_admin_policy(self) -> None:
        client = self._client(_ADMIN_DOCUMENT)
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["has_full_admin_policy"] is True

    def test_scoped_policy_does_not_set_has_full_admin_policy(self) -> None:
        client = self._client(_SCOPED_DOCUMENT)
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["has_full_admin_policy"] is False

    def test_user_with_no_attached_policies_has_no_full_admin_policy(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": [user("alice")]}])
        resource = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()[0]
        assert resource.attributes["has_full_admin_policy"] is False


class TestIamCollectorAccountId:
    def test_account_id_is_threaded_into_resources(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": [user("alice")]}])
        resource = IamCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        ).collect()[0]
        assert resource.account_id == "123456789012"


class FakeIamAccountClient(FakeIamClient):
    def __init__(self, mfa_enabled=False, password_policy=None, password_policy_missing=False):
        super().__init__(user_pages=[])
        self._mfa_enabled = mfa_enabled
        self._password_policy = password_policy
        self._password_policy_missing = password_policy_missing

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 1 if self._mfa_enabled else 0}}

    def get_account_password_policy(self):
        if self._password_policy_missing:
            raise ClientError({"Error": {"Code": "NoSuchEntity", "Message": "none"}}, "GetAccountPasswordPolicy")
        return {"PasswordPolicy": self._password_policy or {}}


class TestIamAccountCollector:
    def test_returns_empty_tuple_when_account_id_is_unavailable(self) -> None:
        client = FakeIamAccountClient()
        collector = IamAccountCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id=None)
        assert collector.collect() == ()

    def test_root_mfa_enabled(self) -> None:
        client = FakeIamAccountClient(mfa_enabled=True, password_policy_missing=True)
        collector = IamAccountCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        resource = collector.collect()[0]
        assert resource.resource_type == "iam_account_summary"
        assert resource.attributes["root_mfa_enabled"] is True
        assert resource.account_id == "123456789012"

    def test_root_mfa_disabled(self) -> None:
        client = FakeIamAccountClient(mfa_enabled=False, password_policy_missing=True)
        collector = IamAccountCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        resource = collector.collect()[0]
        assert resource.attributes["root_mfa_enabled"] is False

    def test_no_password_policy_configured(self) -> None:
        client = FakeIamAccountClient(password_policy_missing=True)
        collector = IamAccountCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        resource = collector.collect()[0]
        assert resource.attributes["has_password_policy"] is False
        assert resource.attributes["password_policy_min_length"] is None

    def test_password_policy_details_are_captured(self) -> None:
        client = FakeIamAccountClient(
            password_policy={
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 24,
            }
        )
        collector = IamAccountCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        resource = collector.collect()[0]
        assert resource.attributes["has_password_policy"] is True
        assert resource.attributes["password_policy_min_length"] == 14
        assert resource.attributes["password_policy_requires_symbols"] is True
        assert resource.attributes["password_policy_max_age_days"] == 90
        assert resource.attributes["password_policy_reuse_prevention"] == 24

    def test_resource_id_is_stable_for_the_same_account(self) -> None:
        client = FakeIamAccountClient(password_policy_missing=True)
        collector = IamAccountCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        first = collector.collect()[0]
        second = collector.collect()[0]
        assert first.resource_id == second.resource_id == ResourceId("iam-account-summary:123456789012")

    def test_service_error_is_translated_and_wrapped(self) -> None:
        class FailingClient(FakeIamAccountClient):
            def get_account_summary(self):
                raise ClientError({"Error": {"Code": "InternalFailure", "Message": "oops"}}, "GetAccountSummary")

        client = FailingClient()
        collector = IamAccountCollector(
            session=FakeSession(client), tenant_id=TENANT, clock=CLOCK, account_id="123456789012"
        )
        with pytest.raises(AwsCollectionError):
            collector.collect()


class TestIamCollectorPagination:
    def test_users_are_combined_across_multiple_pages(self) -> None:
        client = FakeIamClient(
            user_pages=[
                {"Users": [user("alice")]},
                {"Users": [user("bob")]},
            ]
        )
        resources = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()
        assert {str(r.resource_id) for r in resources} == {
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:iam::123456789012:user/bob",
        }


class TestIamCollectorErrors:
    def test_authentication_failure_is_translated_and_wrapped(self) -> None:
        class DenyingClient(FakeIamClient):
            def get_paginator(self, op_name):
                if op_name == "list_users":
                    class _Raising:
                        def paginate(self, **kwargs):
                            raise ClientError(
                                {"Error": {"Code": "InvalidClientTokenId", "Message": "bad"}}, "ListUsers"
                            )

                    return _Raising()
                return super().get_paginator(op_name)

        client = DenyingClient(user_pages=[])
        collector = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK)
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsAuthenticationError)


class TestIamCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        client = FakeIamClient(user_pages=[{"Users": [user("alice")]}])
        first = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()
        second = IamCollector(session=FakeSession(client), tenant_id=TENANT, clock=CLOCK).collect()
        assert first == second
