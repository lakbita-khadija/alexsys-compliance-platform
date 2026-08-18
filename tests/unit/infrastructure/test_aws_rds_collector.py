"""STEP 8B — the RDS DB instance collector and normalizer.

The test that matters most in this file is
`test_publicly_accessible_is_not_mapped_to_public`. RDS's
`PubliclyAccessible` means the instance has a publicly-resolvable
endpoint; it does **not** mean anyone can connect, because the security
group still gates every packet. Mapping it to the analyzer's generic
`public` attribute would raise a critical finding for every correctly
firewalled public-endpoint database in an estate — confidently, which is
worse than not raising it at all.

Everything else follows the established collector contract.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from botocore.exceptions import ClientError

from domain.attack_paths.classification import (
    ResourceRole,
    public_exposure_evidence,
    role_of,
)
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import TenantId
from infrastructure.cloud.aws.errors import AwsCollectionError
from infrastructure.cloud.aws.normalizers.rds import normalize_rds_instance
from infrastructure.cloud.aws.resource_collectors.rds import RdsInstanceCollector

TENANT = TenantId("acme")
ACCOUNT = "111111111111"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REGION = "us-east-1"

ARN = f"arn:aws:rds:{REGION}:{ACCOUNT}:db:prod-orders"
SG = "sg-0a1b2c3d"
SUBNET_A = "subnet-aaaa1111"
SUBNET_B = "subnet-bbbb2222"
VPC = "vpc-0a1b2c3d"


def db_instance(**overrides):
    """A realistic DescribeDBInstances entry."""

    base = {
        "DBInstanceArn": ARN,
        "DBInstanceIdentifier": "prod-orders",
        "Engine": "postgres",
        "EngineVersion": "15.4",
        "DBInstanceStatus": "available",
        "DBInstanceClass": "db.t3.medium",
        "PubliclyAccessible": False,
        "StorageEncrypted": True,
        "KmsKeyId": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/abc-123",
        "BackupRetentionPeriod": 7,
        "MultiAZ": True,
        "DeletionProtection": True,
        "MasterUsername": "dbadmin",
        "IAMDatabaseAuthenticationEnabled": False,
        "AutoMinorVersionUpgrade": True,
        "AvailabilityZone": "us-east-1a",
        "Endpoint": {"Address": "prod-orders.abc.us-east-1.rds.amazonaws.com", "Port": 5432},
        "VpcSecurityGroups": [{"VpcSecurityGroupId": SG, "Status": "active"}],
        "DBSubnetGroup": {
            "DBSubnetGroupName": "prod-subnets",
            "VpcId": VPC,
            "Subnets": [
                {"SubnetIdentifier": SUBNET_B},
                {"SubnetIdentifier": SUBNET_A},
            ],
        },
        "TagList": [{"Key": "env", "Value": "prod"}],
    }
    base.update(overrides)
    return base


def normalize(**overrides):
    return normalize_rds_instance(
        instance=db_instance(**overrides),
        region=REGION,
        tenant_id=TENANT,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


class FakeRdsSession:
    def __init__(self, pages=None, error=None) -> None:
        self._pages = pages if pages is not None else [{"DBInstances": []}]
        self._error = error
        self.region_name = REGION
        self.clients: list[str] = []

    def client(self, service_name: str):
        self.clients.append(service_name)
        assert service_name == "rds", f"unexpected client: {service_name}"
        outer = self

        class _Paginator:
            def paginate(self):
                if outer._error is not None:
                    raise outer._error
                return outer._pages

        class _Client:
            def get_paginator(self, operation: str):
                assert operation == "describe_db_instances"
                return _Paginator()

        return _Client()


def collect(pages=None, error=None):
    session = FakeRdsSession(pages, error)
    collector = RdsInstanceCollector(
        session=session, tenant_id=TENANT, clock=lambda: NOW, account_id=ACCOUNT
    )
    return collector.collect(), session


# ---------------------------------------------------------------------
# The decision this step turns on
# ---------------------------------------------------------------------


class TestExposureIsNotOverstated:
    def test_publicly_accessible_is_not_mapped_to_public(self) -> None:
        """The false positive this module exists to avoid.

        `public` is the cross-provider attribute the analyzer reads as
        "internet-reachable". RDS's `PubliclyAccessible` is weaker: a
        public endpoint still gated by the security group. Mapping it
        across would flag every correctly firewalled database.
        """

        resource = normalize(PubliclyAccessible=True)

        assert resource.attributes["publicly_accessible"] is True
        assert "public" not in resource.attributes
        # And the analyzer sees no exposure evidence from it.
        assert public_exposure_evidence(resource.attributes) == ()

    def test_a_public_instance_produces_no_exposure_evidence_alone(self) -> None:
        assert public_exposure_evidence(normalize(PubliclyAccessible=True).attributes) == ()

    def test_the_endpoint_is_recorded_as_evidence(self) -> None:
        # A responder needs the address to verify reachability
        # themselves; it is configuration, not a credential.
        resource = normalize(PubliclyAccessible=True)
        assert resource.attributes["endpoint_port"] == 5432
        assert "rds.amazonaws.com" in resource.attributes["endpoint_address"]


class TestResourceRole:
    def test_an_rds_instance_is_storage(self) -> None:
        """Data-bearing, so worth reaching.

        Left unclassified it would be OTHER — never an attack path
        target — which would mean collecting the production database and
        treating it as irrelevant to risk.
        """

        from application.graph.build_resource_graph import BuildResourceGraph

        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=[normalize()])
        node = next(n for n in graph.nodes if n.resource_type == "rds_db_instance")
        assert role_of(node) is ResourceRole.STORAGE


# ---------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------


class TestNormalization:
    def test_identity_uses_the_arn(self) -> None:
        # Not the identifier: an ARN is globally unique and is what an
        # IAM policy names, which is what lets an ACCESSES edge match.
        resource = normalize()
        assert str(resource.resource_id) == ARN
        assert resource.resource_type == "rds_db_instance"
        assert resource.cloud_provider is CloudProvider.AWS

    def test_tenant_account_region_and_time(self) -> None:
        resource = normalize()
        assert resource.tenant_id == TENANT
        assert resource.account_id == ACCOUNT
        assert resource.region == REGION
        assert resource.collected_at == NOW

    def test_engine_and_version(self) -> None:
        resource = normalize()
        assert resource.attributes["engine"] == "postgres"
        assert resource.attributes["engine_version"] == "15.4"

    def test_data_protection_attributes(self) -> None:
        resource = normalize()
        assert resource.attributes["storage_encrypted"] is True
        assert "kms" in resource.attributes["kms_key_id"]

    def test_resilience_attributes(self) -> None:
        resource = normalize()
        assert resource.attributes["backup_retention_period"] == 7
        assert resource.attributes["multi_az"] is True
        assert resource.attributes["deletion_protection"] is True

    def test_backup_disabled_is_zero_not_missing(self) -> None:
        # 0 is a real, meaningful value: backups are OFF. It must not be
        # confused with "not collected".
        assert normalize(BackupRetentionPeriod=0).attributes["backup_retention_period"] == 0

    def test_the_master_username_is_kept(self) -> None:
        # A username, not a credential — DescribeDBInstances never
        # returns the password. Redacting it would break the
        # default-username check while protecting nothing.
        assert normalize().attributes["master_username"] == "dbadmin"

    def test_placement_is_attributes_not_edges(self) -> None:
        resource = normalize()
        assert resource.attributes["vpc_id"] == VPC
        assert resource.attributes["subnet_ids"] == [SUBNET_A, SUBNET_B]
        # No subnet or VPC edge — see the audit §3.2.
        targets = {str(r.target_resource_id) for r in resource.relationships}
        assert VPC not in targets
        assert SUBNET_A not in targets

    def test_tags(self) -> None:
        assert normalize().tags == {"env": "prod"}

    def test_missing_optional_blocks_do_not_crash(self) -> None:
        resource = normalize_rds_instance(
            instance={"DBInstanceArn": ARN},
            region=REGION,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert resource.attributes["vpc_id"] is None
        assert resource.attributes["subnet_ids"] == []
        assert resource.attributes["endpoint_address"] is None
        assert resource.relationships == ()

    @pytest.mark.parametrize(
        "field, attribute",
        [
            ("PubliclyAccessible", "publicly_accessible"),
            ("StorageEncrypted", "storage_encrypted"),
            ("MultiAZ", "multi_az"),
            ("DeletionProtection", "deletion_protection"),
            ("IAMDatabaseAuthenticationEnabled", "iam_database_authentication_enabled"),
            ("AutoMinorVersionUpgrade", "auto_minor_version_upgrade"),
        ],
    )
    def test_booleans_default_to_false_when_absent(self, field, attribute) -> None:
        instance = db_instance()
        instance.pop(field, None)
        resource = normalize_rds_instance(
            instance=instance, region=REGION, tenant_id=TENANT, collected_at=NOW
        )
        assert resource.attributes[attribute] is False


class TestSecurityGroupRelationships:
    def test_an_active_group_becomes_attached_to(self) -> None:
        resource = normalize()
        assert len(resource.relationships) == 1
        edge = resource.relationships[0]
        assert edge.relationship_type is RelationshipType.ATTACHED_TO
        assert str(edge.target_resource_id) == SG

    def test_groups_are_sorted(self) -> None:
        resource = normalize(
            VpcSecurityGroups=[
                {"VpcSecurityGroupId": "sg-zzzz", "Status": "active"},
                {"VpcSecurityGroupId": "sg-aaaa", "Status": "active"},
            ]
        )
        assert [str(r.target_resource_id) for r in resource.relationships] == [
            "sg-aaaa",
            "sg-zzzz",
        ]

    @pytest.mark.parametrize("status", ["adding", "removing", "failed"])
    def test_an_inactive_group_produces_no_edge(self, status) -> None:
        # A group mid-attach is not yet governing traffic. Same rule as
        # the internet gateway attachment in STEP 8A: a transient state
        # must not become a security conclusion.
        resource = normalize(
            VpcSecurityGroups=[{"VpcSecurityGroupId": SG, "Status": status}]
        )
        assert resource.relationships == ()

    def test_a_malformed_group_entry_is_skipped(self) -> None:
        resource = normalize(VpcSecurityGroups=[{}, {"Status": "active"}])
        assert resource.relationships == ()

    def test_duplicate_groups_produce_one_edge(self) -> None:
        resource = normalize(
            VpcSecurityGroups=[
                {"VpcSecurityGroupId": SG, "Status": "active"},
                {"VpcSecurityGroupId": SG, "Status": "active"},
            ]
        )
        assert len(resource.relationships) == 1


# ---------------------------------------------------------------------
# Collector contract
# ---------------------------------------------------------------------


class TestCollectorContract:
    def test_a_normal_response_is_collected(self) -> None:
        resources, _ = collect([{"DBInstances": [db_instance()]}])
        assert len(resources) == 1
        assert str(resources[0].resource_id) == ARN

    def test_it_uses_the_rds_client(self) -> None:
        _, session = collect([{"DBInstances": [db_instance()]}])
        assert session.clients == ["rds"]

    def test_an_empty_response_yields_nothing(self) -> None:
        resources, _ = collect([{"DBInstances": []}])
        assert resources == ()

    def test_a_missing_key_yields_nothing(self) -> None:
        resources, _ = collect([{}])
        assert resources == ()

    def test_pagination_is_followed(self) -> None:
        second = db_instance(DBInstanceArn=ARN + "-2")
        resources, _ = collect(
            [{"DBInstances": [db_instance()]}, {"DBInstances": [second]}]
        )
        assert len(resources) == 2

    def test_access_denied_is_translated(self) -> None:
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "DescribeDBInstances"
        )
        with pytest.raises(AwsCollectionError):
            collect(error=error)

    def test_throttling_is_translated(self) -> None:
        error = ClientError(
            {"Error": {"Code": "Throttling", "Message": "slow down"}},
            "DescribeDBInstances",
        )
        with pytest.raises(AwsCollectionError):
            collect(error=error)

    def test_normalization_is_deterministic(self) -> None:
        first, _ = collect([{"DBInstances": [db_instance()]}])
        second, _ = collect([{"DBInstances": [db_instance()]}])
        assert first[0].attributes == second[0].attributes
        assert first[0].relationships == second[0].relationships


class TestNoSecretsCollected:
    def test_no_credential_shaped_attribute_is_produced(self) -> None:
        from infrastructure.persistence.postgres.mappers.redaction import is_secret_key

        resource = normalize()
        offenders = [k for k in resource.attributes if is_secret_key(k)]
        assert offenders == []

    def test_a_password_field_would_be_redacted_at_persistence(self) -> None:
        # DescribeDBInstances never returns one. This asserts the
        # backstop holds if a future field ever did.
        from infrastructure.persistence.postgres.mappers.redaction import redact

        redacted = redact({"master_user_password": "hunter2", "engine": "postgres"})
        assert redacted["master_user_password"] == "[REDACTED]"
        assert redacted["engine"] == "postgres"
