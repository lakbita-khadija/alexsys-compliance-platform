"""STEP 1 — workload → IAM identity relationship.

The governing constraint, restated because it is the whole point of this
module: **an instance profile ARN is not a role ARN**. A profile is a
container that holds a role, and although tooling usually creates them
with matching names, that is a convention. Deriving one from the other
would fabricate a privilege relationship — an assertion that this
workload can act as that identity, which nothing observed.

So most of this file asserts what does **not** get emitted.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.unknown import is_unknown
from infrastructure.cloud.aws import instance_profiles
from infrastructure.cloud.aws.instance_profiles import ProfileResolutionStatus
from infrastructure.cloud.aws.resource_collectors.ec2 import Ec2Collector
from infrastructure.cloud.resilience import RetryPolicy

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731

ACCOUNT = "111111111111"
PROFILE_ARN = f"arn:aws:iam::{ACCOUNT}:instance-profile/AppServerProfile"
#: Deliberately NOT "role/AppServerProfile" — the names differ, so any
#: test that passes by name inference would be caught.
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/completely-different-role-name"


# ---------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class FakeEc2Client:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, op_name):
        assert op_name == "describe_instances"
        return FakePaginator(self._pages)

    def describe_volumes(self, VolumeIds):
        return {"Volumes": []}


class FakeIamClient:
    def __init__(self, *, response=None, error=None, errors_then=None):
        self._response = response
        self._error = error
        #: A list of exceptions to raise before finally succeeding —
        #: used to exercise the retry path without sleeping.
        self._errors_then = list(errors_then or [])
        self.calls: list[str] = []

    def get_instance_profile(self, InstanceProfileName):
        self.calls.append(InstanceProfileName)
        if self._errors_then:
            raise self._errors_then.pop(0)
        if self._error is not None:
            raise self._error
        if self._response is None:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "no"}}, "GetInstanceProfile"
            )
        return self._response


class FakeSession:
    region_name = "eu-west-1"

    def __init__(self, ec2_client, iam_client):
        self._ec2 = ec2_client
        self._iam = iam_client

    def client(self, service_name):
        if service_name == "ec2":
            return self._ec2
        if service_name == "iam":
            return self._iam
        raise AssertionError(service_name)


def profile_response(role_arn=ROLE_ARN, role_name="completely-different-role-name"):
    return {
        "InstanceProfile": {
            "InstanceProfileName": "AppServerProfile",
            "Arn": PROFILE_ARN,
            "Roles": [{"Arn": role_arn, "RoleName": role_name}],
        }
    }


def instance(profile_arn=PROFILE_ARN):
    payload = {
        "InstanceId": "i-web",
        "State": {"Name": "running"},
        "SecurityGroups": [],
        "PublicIpAddress": "203.0.113.10",
    }
    if profile_arn is not None:
        payload["IamInstanceProfile"] = {"Arn": profile_arn}
    return payload


def collect(iam_client, profile_arn=PROFILE_ARN, account_id=ACCOUNT):
    collector = Ec2Collector(
        session=FakeSession(FakeEc2Client([{"Reservations": [{"Instances": [instance(profile_arn)]}]}]), iam_client),
        tenant_id=TENANT,
        clock=CLOCK,
        account_id=account_id,
        retry_policy=RetryPolicy(max_attempts=3, base_delay=0.001, max_delay=0.002),
    )
    return collector.collect()[0]


def identity_edges(resource):
    return [
        r for r in resource.relationships if r.relationship_type is RelationshipType.ASSUMES
    ]


# ---------------------------------------------------------------------
# The nine required unit tests
# ---------------------------------------------------------------------


def test_ec2_instance_profile_resolves_to_iam_role() -> None:
    iam = FakeIamClient(response=profile_response())
    resource = collect(iam)

    edges = identity_edges(resource)
    assert len(edges) == 1
    assert edges[0].target_resource_id == ResourceId(ROLE_ARN)

    # The name differs from the profile name, so this could not have come
    # from string inference.
    assert iam.calls == ["AppServerProfile"]
    assert resource.attributes["instance_profile_role_arn"] == ROLE_ARN
    assert resource.attributes["instance_profile_resolution"] == ProfileResolutionStatus.RESOLVED


def test_ec2_without_instance_profile_emits_no_identity_edge() -> None:
    iam = FakeIamClient()
    resource = collect(iam, profile_arn=None)

    assert identity_edges(resource) == []
    # No API call at all — no profile means nothing to look up.
    assert iam.calls == []
    assert resource.attributes["instance_profile_role_arn"] is None
    assert resource.attributes["instance_profile_resolution"] == ProfileResolutionStatus.NO_PROFILE


def test_instance_profile_access_denied_does_not_fabricate_role() -> None:
    iam = FakeIamClient(
        error=ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetInstanceProfile")
    )
    resource = collect(iam)

    assert identity_edges(resource) == []
    # UNKNOWN, not None: "we could not check" must never read as "this
    # instance has no role".
    assert is_unknown(resource.attributes["instance_profile_role_arn"])
    assert resource.attributes["instance_profile_resolution"] == ProfileResolutionStatus.DENIED
    # The profile ARN we DID observe is still reported.
    assert resource.attributes["instance_profile_arn"] == PROFILE_ARN


def test_missing_instance_profile_is_handled() -> None:
    iam = FakeIamClient()  # defaults to NoSuchEntity
    resource = collect(iam)

    assert identity_edges(resource) == []
    # NOT_FOUND is a determinate fact (a dangling reference), so None —
    # not UNKNOWN.
    assert resource.attributes["instance_profile_role_arn"] is None
    assert resource.attributes["instance_profile_resolution"] == ProfileResolutionStatus.NOT_FOUND


@pytest.mark.parametrize(
    "bad_arn",
    [
        "not-an-arn",
        "arn:aws:iam::111111111111:role/NotAProfile",
        "arn:aws:s3:::a-bucket",
        "arn:aws:iam::111111111111:instance-profile/",
        "arn:aws:iam::111111111111",
        "",
    ],
)
def test_malformed_instance_profile_arn_is_handled(bad_arn: str) -> None:
    iam = FakeIamClient(response=profile_response())
    resource = collect(iam, profile_arn=bad_arn or None)

    assert identity_edges(resource) == []
    # Never call AWS with a name we could not parse.
    assert iam.calls == []
    assert resource.attributes["instance_profile_role_arn"] is None


def test_throttled_get_instance_profile_retries() -> None:
    throttle = ClientError(
        {"Error": {"Code": "Throttling", "Message": "slow down"}}, "GetInstanceProfile"
    )
    iam = FakeIamClient(errors_then=[throttle, throttle], response=profile_response())
    resource = collect(iam)

    # Retried by the SHARED resilience layer — the collector contains no
    # backoff logic of its own.
    assert iam.calls == ["AppServerProfile"] * 3
    assert len(identity_edges(resource)) == 1


def test_resolved_role_preserves_provenance() -> None:
    iam = FakeIamClient(response=profile_response())
    edge = identity_edges(collect(iam))[0]

    assert edge.evidence["instance_profile_arn"] == PROFILE_ARN
    assert edge.evidence["resolved_instance_profile"] == "AppServerProfile"
    assert edge.evidence["resolved_role_arn"] == ROLE_ARN
    assert edge.evidence["resolved_via"] == "iam:GetInstanceProfile"


def test_resolved_role_confidence_is_correct() -> None:
    iam = FakeIamClient(response=profile_response())
    edge = identity_edges(collect(iam))[0]

    # High: both endpoints and the link between them came from AWS
    # responses, with nothing inferred.
    assert edge.confidence == "high"


def test_cross_account_role_is_not_silently_linked() -> None:
    foreign = "arn:aws:iam::999999999999:role/ForeignRole"
    iam = FakeIamClient(response=profile_response(role_arn=foreign, role_name="ForeignRole"))
    resource = collect(iam)

    # AWS does not permit this, so it is an anomaly. The edge is withheld
    # and the anomaly is named rather than being invented as a
    # cross-account privilege relationship.
    assert identity_edges(resource) == []
    assert resource.attributes["instance_profile_resolution"] == ProfileResolutionStatus.CROSS_ACCOUNT
    assert resource.attributes["instance_profile_role_arn"] is None


# ---------------------------------------------------------------------
# Additional safety
# ---------------------------------------------------------------------


def test_profile_holding_no_role_emits_no_edge() -> None:
    empty = {"InstanceProfile": {"InstanceProfileName": "AppServerProfile", "Roles": []}}
    resource = collect(FakeIamClient(response=empty))

    assert identity_edges(resource) == []
    assert resource.attributes["instance_profile_resolution"] == ProfileResolutionStatus.NO_ROLE


def test_role_with_blank_arn_emits_no_edge() -> None:
    blank = {"InstanceProfile": {"Roles": [{"Arn": "   ", "RoleName": "x"}]}}
    resource = collect(FakeIamClient(response=blank))

    assert identity_edges(resource) == []


def test_one_unresolvable_profile_does_not_lose_the_instance() -> None:
    iam = FakeIamClient(error=RuntimeError("something unexpected"))
    resource = collect(iam)

    # The instance is still collected, with every other attribute intact.
    assert str(resource.resource_id) == "i-web"
    assert resource.attributes["public_ip"] == "203.0.113.10"
    assert identity_edges(resource) == []


def test_security_group_edges_are_unaffected() -> None:
    payload = instance()
    payload["SecurityGroups"] = [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}]
    collector = Ec2Collector(
        session=FakeSession(
            FakeEc2Client([{"Reservations": [{"Instances": [payload]}]}]),
            FakeIamClient(response=profile_response()),
        ),
        tenant_id=TENANT,
        clock=CLOCK,
        account_id=ACCOUNT,
    )
    resource = collector.collect()[0]

    attached = [
        r for r in resource.relationships if r.relationship_type is RelationshipType.ATTACHED_TO
    ]
    assert {str(r.target_resource_id) for r in attached} == {"sg-1", "sg-2"}
    assert len(identity_edges(resource)) == 1


class TestArnParsing:
    def test_plain_profile_arn(self) -> None:
        assert instance_profiles.parse_instance_profile_arn(PROFILE_ARN) == (
            ACCOUNT,
            "AppServerProfile",
        )

    def test_profile_arn_with_a_path(self) -> None:
        arn = f"arn:aws:iam::{ACCOUNT}:instance-profile/team/prod/AppServerProfile"
        assert instance_profiles.parse_instance_profile_arn(arn) == (
            ACCOUNT,
            "AppServerProfile",
        )

    @pytest.mark.parametrize(
        "bad", [None, "", "   ", "arn:aws:iam::1:role/R", "nonsense", "arn:aws:iam::1"]
    )
    def test_unparseable_returns_none(self, bad) -> None:
        assert instance_profiles.parse_instance_profile_arn(bad) is None
