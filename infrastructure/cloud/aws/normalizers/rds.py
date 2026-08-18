"""AWS RDS DB instance → ``NormalizedResource`` (STEP 8B).

The single most consequential decision in this module, stated up front:

    `PubliclyAccessible` is NOT normalized to the generic `public`
    attribute.

`public` is the cross-provider name the attack path analyzer reads to
mean "internet-reachable" (`domain/attack_paths/classification.py`), and
RDS's `PubliclyAccessible` does not mean that. It means the instance has
a publicly-resolvable endpoint; the security group still gates every
packet. A publicly-addressable database behind a closed security group is
not exposed.

Mapping it across would raise a critical finding for every correctly
firewalled public-endpoint database in an estate — and would do it
confidently, which is worse. The codebase already draws this line for
EC2, where the workload scenario requires a public address **and**
unrestricted ingress, *"Both halves are required"*. RDS gets the same
treatment: `publicly_accessible` under its own name, and the second half
arriving through the `ATTACHED_TO` security group edge.

Relationships follow `normalizers/ec2.py` exactly — security groups
become `ATTACHED_TO`, and VPC/subnet/KMS references stay plain
attributes because the resource that declares them cannot emit an edge
in the direction those relationships actually point. See
`docs/audits/aws-rds-current-state.md` §3.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId

#: A security group only governs traffic once its attachment is active.
#: Matches the internet-gateway attachment rule from STEP 8A: a
#: transient state must not become a security conclusion.
_ACTIVE = "active"


def _security_group_ids(instance: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                group["VpcSecurityGroupId"]
                for group in instance.get("VpcSecurityGroups", [])
                if group.get("VpcSecurityGroupId") and group.get("Status") == _ACTIVE
            }
        )
    )


def normalize_rds_instance(
    *,
    instance: Mapping[str, Any],
    region: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One RDS DB instance."""

    subnet_group = instance.get("DBSubnetGroup") or {}
    subnet_ids = tuple(
        sorted(
            {
                subnet["SubnetIdentifier"]
                for subnet in subnet_group.get("Subnets", [])
                if subnet.get("SubnetIdentifier")
            }
        )
    )

    endpoint = instance.get("Endpoint") or {}

    attributes: dict[str, Any] = {
        "engine": instance.get("Engine"),
        "engine_version": instance.get("EngineVersion"),
        "status": instance.get("DBInstanceStatus"),
        "instance_class": instance.get("DBInstanceClass"),
        # --- Exposure. Read the module docstring before mapping this to
        # anything else: on its own it is an addressability fact, not an
        # exposure conclusion.
        "publicly_accessible": bool(instance.get("PubliclyAccessible", False)),
        "endpoint_address": endpoint.get("Address"),
        "endpoint_port": endpoint.get("Port"),
        # --- Data protection.
        "storage_encrypted": bool(instance.get("StorageEncrypted", False)),
        "kms_key_id": instance.get("KmsKeyId"),
        "performance_insights_enabled": bool(
            instance.get("PerformanceInsightsEnabled", False)
        ),
        # --- Resilience.
        "backup_retention_period": instance.get("BackupRetentionPeriod"),
        "multi_az": bool(instance.get("MultiAZ", False)),
        "deletion_protection": bool(instance.get("DeletionProtection", False)),
        # --- Access and maintenance.
        # A username, never a credential: DescribeDBInstances does not
        # return the password. Kept because "is the master user still
        # named `admin`" is a real check, and redacting an identifier
        # would break it while protecting nothing.
        "master_username": instance.get("MasterUsername"),
        "iam_database_authentication_enabled": bool(
            instance.get("IAMDatabaseAuthenticationEnabled", False)
        ),
        "auto_minor_version_upgrade": bool(
            instance.get("AutoMinorVersionUpgrade", False)
        ),
        "ca_certificate_identifier": instance.get("CACertificateIdentifier"),
        # --- Placement. Attributes rather than edges — see the audit §3.2.
        "vpc_id": subnet_group.get("VpcId"),
        "subnet_ids": list(subnet_ids),
        "db_subnet_group_name": subnet_group.get("DBSubnetGroupName"),
        "availability_zone": instance.get("AvailabilityZone"),
        # --- Topology we can name but not yet traverse (audit §3.4).
        "db_cluster_identifier": instance.get("DBClusterIdentifier"),
        "read_replica_source": instance.get("ReadReplicaSourceDBInstanceIdentifier"),
        "read_replica_identifiers": sorted(
            instance.get("ReadReplicaDBInstanceIdentifiers", [])
        ),
    }

    relationships = tuple(
        ResourceRelationship(
            target_resource_id=ResourceId(group_id),
            relationship_type=RelationshipType.ATTACHED_TO,
            evidence={
                "source_field": "DescribeDBInstances.DBInstances[].VpcSecurityGroups[]",
                "status": _ACTIVE,
            },
            confidence="high",
        )
        for group_id in _security_group_ids(instance)
    )

    tags = {
        tag["Key"]: tag["Value"] for tag in instance.get("TagList", []) if "Key" in tag
    }

    return NormalizedResource(
        # The ARN, not the identifier: an identifier is unique per region
        # per account, and the graph is account-scoped only by
        # convention. The ARN is globally unique and is what an IAM
        # policy names, which is what lets an ACCESSES edge match.
        resource_id=ResourceId(instance["DBInstanceArn"]),
        resource_type="rds_db_instance",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes=attributes,
        tags=tags,
        relationships=relationships,
        collected_at=collected_at,
        account_id=account_id,
    )


__all__ = ["normalize_rds_instance"]
