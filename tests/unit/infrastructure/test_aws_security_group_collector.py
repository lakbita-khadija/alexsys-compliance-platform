from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError, AwsServiceError
from infrastructure.cloud.aws.resource_collectors.security_groups import SecurityGroupCollector

TENANT = TenantId("acme")
CLOCK = lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)  # noqa: E731


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class FakeEc2Client:
    def __init__(self, pages):
        self._pages = pages

    def get_paginator(self, op_name):
        assert op_name == "describe_security_groups"
        return FakePaginator(self._pages)


class FakeSession:
    region_name = "eu-west-1"

    def __init__(self, client):
        self._client = client

    def client(self, service_name):
        assert service_name == "ec2"
        return self._client


def make_collector(pages):
    return SecurityGroupCollector(session=FakeSession(FakeEc2Client(pages)), tenant_id=TENANT, clock=CLOCK)


def sg(group_id, vpc_id="vpc-1", ingress=None, egress=None, tags=None):
    return {
        "GroupId": group_id,
        "VpcId": vpc_id,
        "IpPermissions": ingress or [],
        "IpPermissionsEgress": egress or [],
        "Tags": tags or [],
    }


class TestSecurityGroupCollectorBasics:
    def test_collects_a_restrictive_security_group(self) -> None:
        rule = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}
        resources = make_collector([{"SecurityGroups": [sg("sg-restrictive", ingress=[rule])]}]).collect()
        resource = resources[0]
        assert resource.resource_id == ResourceId("sg-restrictive")
        assert resource.resource_type == "security_group"
        assert resource.attributes["has_unrestricted_ingress"] is False
        assert resource.attributes["unrestricted_ingress_ports"] == ()

    def test_collects_an_insecure_security_group(self) -> None:
        rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        resources = make_collector([{"SecurityGroups": [sg("sg-open", ingress=[rule])]}]).collect()
        resource = resources[0]
        assert resource.attributes["has_unrestricted_ingress"] is True
        assert resource.attributes["unrestricted_ingress_ports"] == (22,)

    def test_ipv6_unrestricted_cidr_is_detected(self) -> None:
        rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}
        resource = make_collector([{"SecurityGroups": [sg("sg-open6", ingress=[rule])]}]).collect()[0]
        assert resource.attributes["has_unrestricted_ingress"] is True

    def test_port_range_rule_sets_has_unrestricted_flag_without_enumerating_every_port(self) -> None:
        rule = {"IpProtocol": "tcp", "FromPort": 20, "ToPort": 25, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        resource = make_collector([{"SecurityGroups": [sg("sg-range", ingress=[rule])]}]).collect()[0]
        assert resource.attributes["has_unrestricted_ingress"] is True
        assert resource.attributes["unrestricted_ingress_ports"] == ()

    def test_region_comes_from_the_session(self) -> None:
        resource = make_collector([{"SecurityGroups": [sg("sg-1")]}]).collect()[0]
        assert resource.region == "eu-west-1"

    def test_vpc_id_is_preserved(self) -> None:
        resource = make_collector([{"SecurityGroups": [sg("sg-1", vpc_id="vpc-999")]}]).collect()[0]
        assert resource.attributes["vpc_id"] == "vpc-999"

    def test_ingress_and_egress_rule_counts(self) -> None:
        ingress = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
        egress = [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]
        resource = make_collector([{"SecurityGroups": [sg("sg-1", ingress=ingress, egress=egress)]}]).collect()[0]
        assert resource.attributes["ingress_rule_count"] == 1
        assert resource.attributes["egress_rule_count"] == 1

    def test_empty_account_returns_empty_tuple(self) -> None:
        resources = make_collector([{"SecurityGroups": []}]).collect()
        assert resources == ()


class TestSecurityGroupRelationships:
    def test_referenced_security_group_becomes_an_allows_relationship(self) -> None:
        ingress = [
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "UserIdGroupPairs": [{"GroupId": "sg-app"}],
            }
        ]
        resource = make_collector([{"SecurityGroups": [sg("sg-db", ingress=ingress)]}]).collect()[0]
        assert len(resource.relationships) == 1
        relationship = resource.relationships[0]
        assert relationship.target_resource_id == ResourceId("sg-app")
        assert relationship.relationship_type is RelationshipType.ALLOWS


class TestSecurityGroupCollectorPagination:
    def test_security_groups_are_combined_across_multiple_pages(self) -> None:
        pages = [
            {"SecurityGroups": [sg("sg-1")]},
            {"SecurityGroups": [sg("sg-2")]},
        ]
        resources = make_collector(pages).collect()
        assert {str(r.resource_id) for r in resources} == {"sg-1", "sg-2"}


class TestSecurityGroupCollectorErrors:
    def test_service_error_is_translated_and_wrapped(self) -> None:
        class ThrottlingClient(FakeEc2Client):
            def get_paginator(self, op_name):
                class _Raising:
                    def paginate(self):
                        raise ClientError({"Error": {"Code": "Throttling", "Message": "slow down"}}, "DescribeSecurityGroups")

                return _Raising()

        collector = SecurityGroupCollector(
            session=FakeSession(ThrottlingClient([])), tenant_id=TENANT, clock=CLOCK
        )
        with pytest.raises(AwsCollectionError) as exc_info:
            collector.collect()
        assert isinstance(exc_info.value.__cause__, AwsServiceError)


class TestSecurityGroupCollectorDeterminism:
    def test_collection_is_deterministic(self) -> None:
        pages = [{"SecurityGroups": [sg("sg-1")]}]
        first = make_collector(pages).collect()
        second = make_collector(pages).collect()
        assert first == second


class TestSecurityGroupCollectorAccountId:
    def test_account_id_is_threaded_into_resources(self) -> None:
        session = FakeSession(FakeEc2Client([{"SecurityGroups": [sg("sg-1")]}]))
        collector = SecurityGroupCollector(session=session, tenant_id=TENANT, clock=CLOCK, account_id="123456789012")
        resource = collector.collect()[0]
        assert resource.account_id == "123456789012"
