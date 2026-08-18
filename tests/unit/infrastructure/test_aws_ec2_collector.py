from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError, AwsServiceError
from infrastructure.cloud.aws.resource_collectors.ec2 import Ec2Collector

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class FakeEc2Client:
    def __init__(self, pages, volumes_by_id=None):
        self._pages = pages
        self._volumes_by_id = volumes_by_id or {}

    def get_paginator(self, op_name):
        assert op_name == "describe_instances"
        return FakePaginator(self._pages)

    def describe_volumes(self, VolumeIds):
        return {"Volumes": [self._volumes_by_id[vid] for vid in VolumeIds if vid in self._volumes_by_id]}


class FakeIamClient:
    """Serves ``iam:GetInstanceProfile`` for instance-profile resolution.

    Default behaviour is "no profile exists", so every pre-existing test
    — none of which sets an instance profile — resolves to NOT_FOUND and
    emits no identity edge, exactly as before this call was added.
    """

    def __init__(self, profiles_by_name=None, error=None):
        self._profiles = profiles_by_name or {}
        self._error = error
        self.calls: list[str] = []

    def get_instance_profile(self, InstanceProfileName):
        self.calls.append(InstanceProfileName)
        if self._error is not None:
            raise self._error
        if InstanceProfileName not in self._profiles:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "not found"}},
                "GetInstanceProfile",
            )
        return {"InstanceProfile": self._profiles[InstanceProfileName]}


class FakeSession:
    """Serves the ec2 client and the iam client.

    The previous version asserted ``service_name == "ec2"``. That pinned
    a fixture detail — that the collector used exactly one client — not a
    behaviour anyone intended. Resolving an instance profile legitimately
    needs the IAM client, so the fake now serves both and still refuses
    any third service.
    """

    region_name = "eu-west-1"

    def __init__(self, client, iam_client=None):
        self._client = client
        self._iam_client = iam_client or FakeIamClient()

    def client(self, service_name):
        if service_name == "ec2":
            return self._client
        if service_name == "iam":
            return self._iam_client
        raise AssertionError(f"unexpected client requested: {service_name}")


def make_collector(pages, volumes_by_id=None, account_id=None, iam_client=None):
    return Ec2Collector(
        session=FakeSession(FakeEc2Client(pages, volumes_by_id), iam_client),
        tenant_id=TENANT,
        clock=CLOCK,
        account_id=account_id,
    )


def instance(
    instance_id,
    state="running",
    security_groups=None,
    subnet_id="subnet-1",
    vpc_id="vpc-1",
    tags=None,
    public_ip=None,
    instance_profile_arn=None,
    imds_v2_required=False,
    root_device_name=None,
    root_volume_id=None,
):
    result = {
        "InstanceId": instance_id,
        "State": {"Name": state},
        "SecurityGroups": security_groups or [],
        "SubnetId": subnet_id,
        "VpcId": vpc_id,
        "Tags": tags or [],
        "MetadataOptions": {"HttpTokens": "required" if imds_v2_required else "optional"},
    }
    if public_ip is not None:
        result["PublicIpAddress"] = public_ip
    if instance_profile_arn is not None:
        result["IamInstanceProfile"] = {"Arn": instance_profile_arn}
    if root_device_name is not None:
        result["RootDeviceName"] = root_device_name
        result["BlockDeviceMappings"] = [
            {"DeviceName": root_device_name, "Ebs": {"VolumeId": root_volume_id}}
        ]
    return result


def reservation(*instances):
    return {"Reservations": [{"Instances": list(instances)}]}


class TestEc2CollectorBasics:
    def test_collects_a_running_instance(self) -> None:
        resources = make_collector([reservation(instance("i-1"))]).collect()
        resource = resources[0]
        assert resource.resource_id == ResourceId("i-1")
        assert resource.resource_type == "ec2_instance"
        assert resource.attributes["state"] == "running"
        assert resource.region == "eu-west-1"

    def test_vpc_and_subnet_are_captured(self) -> None:
        resource = make_collector([reservation(instance("i-1", subnet_id="subnet-9", vpc_id="vpc-9"))]).collect()[0]
        assert resource.attributes["subnet_id"] == "subnet-9"
        assert resource.attributes["vpc_id"] == "vpc-9"

    def test_tags_are_captured(self) -> None:
        resource = make_collector(
            [reservation(instance("i-1", tags=[{"Key": "env", "Value": "test"}]))]
        ).collect()[0]
        assert resource.tags == {"env": "test"}

    def test_empty_account_returns_empty_tuple(self) -> None:
        resources = make_collector([{"Reservations": []}]).collect()
        assert resources == ()

    def test_multiple_instances_across_multiple_reservations(self) -> None:
        page = {
            "Reservations": [
                {"Instances": [instance("i-1")]},
                {"Instances": [instance("i-2")]},
            ]
        }
        resources = make_collector([page]).collect()
        assert {str(r.resource_id) for r in resources} == {"i-1", "i-2"}


class TestEc2SecurityGroupRelationships:
    """Security-group edges only.

    Both tests pin ``subnet_id=None`` so that the exact-count and
    exact-empty assertions keep meaning what their names say. They
    previously used "all relationships" as a stand-in for "the security
    group relationships", which was only true while the instance had no
    other edge to emit; STEP 8A.1 gave it one. The assertions are not
    relaxed — the subnet edge, and its coexistence with these, is
    asserted exactly in ``test_aws_ec2_subnet_placement.py``.
    """

    def test_attached_security_groups_become_attached_to_relationships(self) -> None:
        resource = make_collector(
            [
                reservation(
                    instance(
                        "i-1",
                        security_groups=[{"GroupId": "sg-1"}, {"GroupId": "sg-2"}],
                        subnet_id=None,
                    )
                )
            ]
        ).collect()[0]
        assert len(resource.relationships) == 2
        targets = {r.target_resource_id for r in resource.relationships}
        assert targets == {ResourceId("sg-1"), ResourceId("sg-2")}
        assert all(r.relationship_type is RelationshipType.ATTACHED_TO for r in resource.relationships)

    def test_instance_with_no_security_groups_has_no_relationships(self) -> None:
        resource = make_collector(
            [reservation(instance("i-1", security_groups=[], subnet_id=None))]
        ).collect()[0]
        assert resource.relationships == ()


class TestEc2CollectorPagination:
    def test_instances_are_combined_across_multiple_pages(self) -> None:
        pages = [reservation(instance("i-1")), reservation(instance("i-2"))]
        resources = make_collector(pages).collect()
        assert {str(r.resource_id) for r in resources} == {"i-1", "i-2"}


class TestEc2CollectorErrors:
    def test_service_error_is_translated_and_wrapped(self) -> None:
        class ThrottlingClient(FakeEc2Client):
            def get_paginator(self, op_name):
                class _Raising:
                    def paginate(self):
                        raise ClientError({"Error": {"Code": "RequestLimitExceeded", "Message": "slow"}}, "DescribeInstances")

                return _Raising()

        collector = Ec2Collector(session=FakeSession(ThrottlingClient([])), tenant_id=TENANT, clock=CLOCK)
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsServiceError)


class TestEc2CollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        pages = [reservation(instance("i-1"))]
        first = make_collector(pages).collect()
        second = make_collector(pages).collect()
        assert first == second


class TestEc2CollectorExposureAndHardening:
    def test_public_ip_is_captured(self) -> None:
        resource = make_collector([reservation(instance("i-1", public_ip="203.0.113.5"))]).collect()[0]
        assert resource.attributes["public_ip"] == "203.0.113.5"

    def test_public_ip_defaults_to_none(self) -> None:
        resource = make_collector([reservation(instance("i-1"))]).collect()[0]
        assert resource.attributes["public_ip"] is None

    def test_instance_profile_arn_is_captured(self) -> None:
        resource = make_collector(
            [reservation(instance("i-1", instance_profile_arn="arn:aws:iam::123:instance-profile/role"))]
        ).collect()[0]
        assert resource.attributes["instance_profile_arn"] == "arn:aws:iam::123:instance-profile/role"

    def test_imds_v2_required_true(self) -> None:
        resource = make_collector([reservation(instance("i-1", imds_v2_required=True))]).collect()[0]
        assert resource.attributes["imds_v2_required"] is True

    def test_imds_v2_required_false(self) -> None:
        resource = make_collector([reservation(instance("i-1", imds_v2_required=False))]).collect()[0]
        assert resource.attributes["imds_v2_required"] is False

    def test_root_volume_encrypted_true(self) -> None:
        pages = [reservation(instance("i-1", root_device_name="/dev/xvda", root_volume_id="vol-1"))]
        resource = make_collector(pages, volumes_by_id={"vol-1": {"Encrypted": True}}).collect()[0]
        assert resource.attributes["root_volume_encrypted"] is True

    def test_root_volume_encrypted_false(self) -> None:
        pages = [reservation(instance("i-1", root_device_name="/dev/xvda", root_volume_id="vol-1"))]
        resource = make_collector(pages, volumes_by_id={"vol-1": {"Encrypted": False}}).collect()[0]
        assert resource.attributes["root_volume_encrypted"] is False

    def test_root_volume_encrypted_is_none_when_no_ebs_root_device(self) -> None:
        resource = make_collector([reservation(instance("i-1"))]).collect()[0]
        assert resource.attributes["root_volume_encrypted"] is None

    def test_account_id_is_threaded_into_resources(self) -> None:
        resource = make_collector([reservation(instance("i-1"))], account_id="123456789012").collect()[0]
        assert resource.account_id == "123456789012"
