"""Tests for the IAM role collector (§4.1, §33).

Covers the failure modes §33 lists: happy path, empty response,
pagination, API failure, throttling, permission denied, malformed
resource, missing optional fields.

The permission-denied cases carry the most weight. They assert that a
denied call produces UNKNOWN rather than a confident `False`, which is
the difference between "we could not read this role's policies" and
"this role has no dangerous policies" — the second being a false
negative that nobody investigates.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from domain.shared.identifiers import TenantId
from domain.shared.unknown import is_unknown
from infrastructure.cloud.aws.errors import AwsError
from infrastructure.cloud.aws.resource_collectors.iam_roles import IamRoleCollector
from infrastructure.cloud.resilience import RetryPolicy

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
TENANT = TenantId("acme")
ACCOUNT = "111111111111"

ADMIN_DOC = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
SAFE_DOC = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}

EC2_TRUST = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT}},
        }
    ]
}
PUBLIC_TRUST = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]}


class Denied(Exception):
    def __init__(self) -> None:
        super().__init__("AccessDenied")
        self.response = {"Error": {"Code": "AccessDenied"}}


class Throttled(Exception):
    def __init__(self) -> None:
        super().__init__("Throttling")
        self.response = {"Error": {"Code": "Throttling"}}


class FakePaginator:
    def __init__(self, pages, fail_with=None, fail_on_page=None):
        self._pages = pages
        self._fail_with = fail_with
        self._fail_on_page = fail_on_page

    def paginate(self, **kwargs):
        for index, page in enumerate(self._pages):
            if self._fail_with and index == self._fail_on_page:
                raise self._fail_with
            yield page


class FakeIamClient:
    """Minimal stand-in for the boto3 IAM client."""

    def __init__(
        self,
        *,
        roles,
        attached=None,
        inline=None,
        policy_documents=None,
        deny_policy_listing=False,
        deny_get_role=False,
        role_pages=None,
    ):
        self._roles = roles
        self._attached = attached or {}
        self._inline = inline or {}
        self._policy_documents = policy_documents or {}
        self._deny_policy_listing = deny_policy_listing
        self._deny_get_role = deny_get_role
        self._role_pages = role_pages
        self.calls: list[str] = []

    def get_paginator(self, operation):
        self.calls.append(operation)
        if operation == "list_roles":
            pages = self._role_pages or [{"Roles": self._roles}]
            return FakePaginator(pages)
        if operation == "list_attached_role_policies":
            if self._deny_policy_listing:
                return FakePaginator([{}], fail_with=Denied(), fail_on_page=0)
            return FakePaginator(
                [{"AttachedPolicies": [
                    {"PolicyName": n, "PolicyArn": f"arn:aws:iam::aws:policy/{n}"}
                    for n in self._attached.get(_current_role(), [])
                ]}]
            )
        if operation == "list_role_policies":
            return FakePaginator([{"PolicyNames": self._inline.get(_current_role(), [])}])
        raise AssertionError(f"unexpected paginator: {operation}")

    def get_policy(self, PolicyArn):  # noqa: N803 - boto3 casing
        self.calls.append("get_policy")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):  # noqa: N803
        self.calls.append("get_policy_version")
        name = PolicyArn.rsplit("/", 1)[-1]
        return {"PolicyVersion": {"Document": self._policy_documents.get(name, SAFE_DOC)}}

    def get_role_policy(self, RoleName, PolicyName):  # noqa: N803
        self.calls.append("get_role_policy")
        return {"PolicyDocument": self._policy_documents.get(PolicyName, SAFE_DOC)}

    def get_role(self, RoleName):  # noqa: N803
        self.calls.append("get_role")
        if self._deny_get_role:
            raise Denied()
        return {"Role": {"RoleLastUsed": {"LastUsedDate": NOW}}}


_ROLE_CONTEXT = {"name": ""}


def _current_role() -> str:
    return _ROLE_CONTEXT["name"]


class FakeSession:
    def __init__(self, client):
        self._client = client

    def client(self, service):
        return self._client


def a_role(name="app-role", *, trust=None, path="/"):
    return {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:role{path}{name}",
        "Path": path,
        "CreateDate": NOW,
        "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": trust if trust is not None else EC2_TRUST,
    }


def collect(client, **kwargs):
    _ROLE_CONTEXT["name"] = "app-role"
    collector = IamRoleCollector(
        session=FakeSession(client),
        tenant_id=TENANT,
        clock=lambda: NOW,
        account_id=ACCOUNT,
        retry_policy=RetryPolicy(max_attempts=2, base_delay=0.001),
        **kwargs,
    )
    return collector, collector.collect()


class TestHappyPath:
    def test_a_role_is_collected_and_normalized(self) -> None:
        _, resources = collect(FakeIamClient(roles=[a_role()]))
        assert len(resources) == 1
        resource = resources[0]
        assert resource.resource_type == "iam_role"
        assert resource.attributes["role_name"] == "app-role"
        assert resource.region is None, "IAM is global"

    def test_trust_analysis_runs_from_list_roles_alone(self) -> None:
        # The trust document arrives inline, so the most valuable
        # analysis needs only iam:ListRoles.
        _, resources = collect(FakeIamClient(roles=[a_role(trust=PUBLIC_TRUST)]))
        assert resources[0].attributes["is_publicly_assumable"] is True

    def test_a_scoped_trust_policy_is_not_flagged(self) -> None:
        _, resources = collect(FakeIamClient(roles=[a_role(trust=EC2_TRUST)]))
        attributes = resources[0].attributes
        assert attributes["is_publicly_assumable"] is False
        assert attributes["has_confused_deputy_risk"] is False

    def test_a_managed_admin_policy_is_detected_semantically(self) -> None:
        client = FakeIamClient(
            roles=[a_role()],
            attached={"app-role": ["DeveloperAccess"]},
            policy_documents={"DeveloperAccess": ADMIN_DOC},
        )
        _, resources = collect(client)
        # Name says "Developer"; contents say admin. Name matching would
        # miss this entirely.
        assert resources[0].attributes["has_administrator_access"] is True

    def test_service_linked_roles_are_marked(self) -> None:
        _, resources = collect(
            FakeIamClient(roles=[a_role(path="/aws-service-role/")])
        )
        assert resources[0].attributes["is_service_role"] is True

    def test_empty_account_yields_no_resources(self) -> None:
        _, resources = collect(FakeIamClient(roles=[]))
        assert resources == ()


class TestPagination:
    def test_every_page_is_collected(self) -> None:
        client = FakeIamClient(
            roles=[],
            role_pages=[
                {"Roles": [a_role("role-1")]},
                {"Roles": [a_role("role-2")]},
                {"Roles": [a_role("role-3")]},
            ],
        )
        _, resources = collect(client)
        assert len(resources) == 3, "silent truncation is the worst failure mode"


class TestPermissionDenied:
    def test_denied_policy_listing_yields_unknown_not_false(self) -> None:
        # THE test. A denied call must never render as "no dangerous
        # policies" — that is a false negative nobody investigates.
        _, resources = collect(FakeIamClient(roles=[a_role()], deny_policy_listing=True))
        attributes = resources[0].attributes

        assert is_unknown(attributes["has_administrator_access"])
        assert is_unknown(attributes["has_privilege_escalation_path"])
        assert is_unknown(attributes["attached_policy_count"])
        assert attributes["policy_analysis_confidence"] == "unknown"

    def test_the_role_is_still_collected_when_policies_are_denied(self) -> None:
        # Degraded, not dropped: trust analysis still works and is the
        # higher-value signal.
        _, resources = collect(FakeIamClient(roles=[a_role(trust=PUBLIC_TRUST)], deny_policy_listing=True))
        assert len(resources) == 1
        assert resources[0].attributes["is_publicly_assumable"] is True

    def test_denied_get_role_yields_unknown_last_used(self) -> None:
        # Reporting a role as "never used" because of a permission error
        # would recommend deleting a role that is in daily use.
        _, resources = collect(FakeIamClient(roles=[a_role()], deny_get_role=True))
        assert is_unknown(resources[0].attributes["last_used"])

    def test_a_genuinely_unused_role_is_known_not_unknown(self) -> None:
        class NeverUsed(FakeIamClient):
            def get_role(self, RoleName):  # noqa: N803
                return {"Role": {"RoleLastUsed": {}}}

        _, resources = collect(NeverUsed(roles=[a_role()]))
        # AWS returning an empty RoleLastUsed is a KNOWN fact.
        assert resources[0].attributes["last_used"] is None
        assert not is_unknown(resources[0].attributes["last_used"])


class TestFailureIsolation:
    def test_one_broken_role_does_not_lose_the_others(self) -> None:
        # §3: 10,000 resources, one fails, 9,999 still collected.
        roles = [a_role("good-1"), {"NoRoleNameKey": True}, a_role("good-2")]
        collector, resources = collect(FakeIamClient(roles=roles))

        assert len(resources) == 2
        assert collector.stats.skipped_resources == 1
        assert collector.stats.degraded is True

    def test_a_fatal_list_failure_raises_a_typed_error(self) -> None:
        class BrokenClient(FakeIamClient):
            def get_paginator(self, operation):
                raise Denied()

        with pytest.raises(AwsError):
            collect(BrokenClient(roles=[]))


class TestThrottling:
    def test_a_throttle_mid_pagination_raises_rather_than_truncating(self) -> None:
        """A throttle between pages must never yield a short result.

        This is the guarantee that is actually achievable, and the
        distinction matters enough to state precisely.

        A generator that raises is **finalized** (PEP 342), and boto3's
        paginators are generators. Once a throttle escapes one, it cannot
        be resumed — every later `next()` raises StopIteration. So the
        honest contract is not "recover the remaining pages", it is
        "never pretend the truncated result was complete".

        Mid-pagination throttles are prevented rather than recovered, by
        boto3's adaptive retry mode configured on the session, which
        retries *inside* the SDK before the generator ever sees an error.
        This layer is the backstop for when that is exhausted.
        """

        pages = [{"Roles": [a_role("role-1")]}, {"Roles": [a_role("role-2")]}]

        class ThrottlingPaginator:
            def paginate(self, **kwargs):
                yield pages[0]
                raise Throttled()

        class ThrottlingClient(FakeIamClient):
            def get_paginator(self, operation):
                if operation == "list_roles":
                    return ThrottlingPaginator()
                return super().get_paginator(operation)

        collector = IamRoleCollector(
            session=FakeSession(ThrottlingClient(roles=[])),
            tenant_id=TENANT,
            clock=lambda: NOW,
            account_id=ACCOUNT,
            retry_policy=RetryPolicy(max_attempts=2, base_delay=0.001),
        )

        # The failure this asserts against: returning [role-1] and
        # reporting success, so the account looks like it has one role
        # when it has two.
        with pytest.raises(AwsError):
            collector.collect()

        assert collector.stats.throttled >= 1

    def test_a_persistent_throttle_raises_rather_than_truncating(self) -> None:
        class AlwaysThrottled:
            def paginate(self, **kwargs):
                raise Throttled()
                yield  # pragma: no cover - unreachable, makes this a generator

        class ThrottledClient(FakeIamClient):
            def get_paginator(self, operation):
                if operation == "list_roles":
                    return AlwaysThrottled()
                return super().get_paginator(operation)

        collector = IamRoleCollector(
            session=FakeSession(ThrottledClient(roles=[])),
            tenant_id=TENANT,
            clock=lambda: NOW,
            account_id=ACCOUNT,
            retry_policy=RetryPolicy(max_attempts=2, base_delay=0.001),
        )
        # Exhausting the budget must surface as an error, never as an
        # empty-but-successful collection.
        with pytest.raises(AwsError):
            collector.collect()


class TestRelationships:
    def test_a_public_role_emits_a_publicly_exposed_edge(self) -> None:
        _, resources = collect(FakeIamClient(roles=[a_role(trust=PUBLIC_TRUST)]))
        types = {r.relationship_type.value for r in resources[0].relationships}
        assert "publicly_exposed" in types

    def test_a_service_trust_emits_an_assumes_edge(self) -> None:
        _, resources = collect(FakeIamClient(roles=[a_role(trust=EC2_TRUST)]))
        edges = resources[0].relationships
        assert any(r.relationship_type.value == "assumes" for r in edges)
        assert any("ec2.amazonaws.com" in str(r.target_resource_id) for r in edges)

    def test_cross_account_trust_emits_an_account_edge(self) -> None:
        external = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        _, resources = collect(FakeIamClient(roles=[a_role(trust=external)]))
        assert any(
            "999999999999" in str(r.target_resource_id)
            for r in resources[0].relationships
        )


class TestMissingOptionalFields:
    def test_absent_optional_fields_do_not_crash(self) -> None:
        minimal = {"RoleName": "bare", "Arn": f"arn:aws:iam::{ACCOUNT}:role/bare"}
        _, resources = collect(FakeIamClient(roles=[minimal]))
        assert len(resources) == 1
        assert resources[0].attributes["max_session_duration"] is None

    def test_a_malformed_trust_document_is_tolerated(self) -> None:
        _, resources = collect(FakeIamClient(roles=[a_role(trust="not-a-document")]))
        assert resources[0].attributes["is_publicly_assumable"] is False
