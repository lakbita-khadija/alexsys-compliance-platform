"""AWS EC2 instance -> ``NormalizedResource`` (blueprint §6/§24, Phase 3).

Attached security groups become ``ATTACHED_TO`` relationships to the
security group's own ``NormalizedResource`` — both are real,
already-collected resources in the same scan, so this never risks the
``__internet__``/``GraphIntegrityViolation`` problem documented in
``normalizers/s3.py``. No VPC/subnet graph relationship is created:
the closed ``RelationshipType`` vocabulary (blueprint §10) has no
``CONTAINS``-for-network-topology precedent specified for this case,
and inventing one isn't necessary — ``vpc_id``/``subnet_id`` are
captured as plain attributes instead.

An ``ASSUMES`` relationship to the instance's IAM role is emitted **only**
when the collector supplied a resolution that actually succeeded — see
``infrastructure/cloud/aws/instance_profiles.py`` for why the role is
never derived from the instance profile ARN by name.
"""

from __future__ import annotations

from datetime import datetime

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.unknown import UNKNOWN
from infrastructure.cloud.aws.instance_profiles import (
    InstanceProfileResolution,
    ProfileResolutionStatus,
)


def normalize_ec2_instance(
    *,
    instance_id: str,
    state: str,
    region: str,
    vpc_id: str | None,
    subnet_id: str | None,
    security_group_ids: tuple[str, ...],
    public_ip: str | None = None,
    instance_profile_arn: str | None = None,
    instance_profile_resolution: InstanceProfileResolution | None = None,
    imds_v2_required: bool = False,
    root_volume_encrypted: bool | None = None,
    tags: dict[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    relationships = [
        ResourceRelationship(
            target_resource_id=ResourceId(group_id),
            relationship_type=RelationshipType.ATTACHED_TO,
        )
        for group_id in security_group_ids
    ]

    # --- Workload -> subnet placement (STEP 8A.1).
    #
    # `subnet_id` has been collected since Phase 3; what was missing was
    # the EDGE, so the workload could not be located in the network
    # topology STEP 8A built. (Earlier audits in this repository stated
    # that `SubnetId` was not collected at all — that was wrong, and the
    # corrected reading is recorded in
    # docs/audits/aws-network-completion.md §2.)
    #
    # ATTACHED_TO rather than CONTAINS, and the choice is a real
    # trade-off rather than an obvious call:
    #
    # * CONTAINS would match `vpc --CONTAINS--> subnet` and read as pure
    #   containment — but it points container -> contained, and the
    #   INSTANCE is what declares its subnet. Emitting it in that
    #   direction would need the subnet collector to call
    #   DescribeInstances, doubling the heaviest API call in the scan for
    #   directional elegance.
    # * ATTACHED_TO is what this same normalizer already emits for
    #   security groups, and an instance genuinely attaches to a subnet
    #   through its network interface. `target_type` disambiguates the
    #   two in any rule, so nothing is ambiguous downstream.
    #
    # Informational either way: an attacker does not travel INTO a
    # subnet. This adds topology, not attack surface.
    if subnet_id:
        relationships.append(
            ResourceRelationship(
                target_resource_id=ResourceId(subnet_id),
                relationship_type=RelationshipType.ATTACHED_TO,
                evidence={"source_field": "DescribeInstances.Reservations[].Instances[].SubnetId"},
                confidence="high",
            )
        )

    # --- Workload -> identity.
    #
    # ASSUMES is reused rather than a new relationship type being
    # invented: "this workload can act as this identity" is exactly what
    # ASSUMES already means where IamRoleCollector emits it, and it is
    # already classified traversable. A second type with the same meaning
    # would split every query that reasons about identity use.
    #
    # Emitted ONLY on a successful resolution. Every other outcome —
    # denied, not found, malformed, no role, cross-account — produces no
    # edge, because an edge here asserts a privilege relationship and an
    # unverified one is worse than a missing one.
    resolution = instance_profile_resolution
    if resolution is not None and resolution.is_resolved and resolution.role_arn:
        relationships.append(
            ResourceRelationship(
                target_resource_id=ResourceId(resolution.role_arn),
                relationship_type=RelationshipType.ASSUMES,
                evidence={
                    "instance_profile_arn": resolution.profile_arn,
                    "resolved_instance_profile": resolution.profile_name,
                    "resolved_role_arn": resolution.role_arn,
                    "resolved_role_name": resolution.role_name,
                    "resolved_via": "iam:GetInstanceProfile",
                },
                # High: both endpoints and the link between them came
                # from AWS responses, with nothing inferred.
                confidence="high",
            )
        )

    return NormalizedResource(
        resource_id=ResourceId(instance_id),
        resource_type="ec2_instance",
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant_id,
        region=region,
        attributes={
            "state": state,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "public_ip": public_ip,
            "instance_profile_arn": instance_profile_arn,
            # The resolved role, and WHY it is or is not known. UNKNOWN
            # (not None) when the lookup was denied: "we could not check"
            # must never read as "this instance has no role".
            "instance_profile_role_arn": _role_arn_attribute(resolution),
            "instance_profile_resolution": (
                resolution.status if resolution is not None else None
            ),
            "imds_v2_required": imds_v2_required,
            # `None` when the root device isn't an EBS volume (e.g. an
            # instance-store-backed AMI) — encryption doesn't apply,
            # which is a different fact than "unencrypted".
            "root_volume_encrypted": root_volume_encrypted,
        },
        tags=tags,
        relationships=tuple(relationships),
        collected_at=collected_at,
        account_id=account_id,
    )


def _role_arn_attribute(resolution: InstanceProfileResolution | None):
    """The role ARN, ``None``, or ``UNKNOWN``.

    ``UNKNOWN`` exactly when the lookup was prevented (``DENIED``). Every
    other non-resolving status is a determinate fact — there is no
    profile, it does not exist, it holds no role — and ``None`` states
    that correctly. Conflating the two would let a missing permission
    read as a configuration fact.
    """

    if resolution is None:
        return None
    if resolution.is_resolved:
        return resolution.role_arn
    if resolution.status == ProfileResolutionStatus.DENIED:
        return UNKNOWN
    return None
