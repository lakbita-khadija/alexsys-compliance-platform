"""Azure Virtual Machine -> ``NormalizedResource``.

The Azure counterpart of ``normalizers/ec2.py``, including its
relationship handling: an attached Network Security Group becomes an
``ATTACHED_TO`` relationship to that NSG's own ``NormalizedResource``.
Both are real, already-collected resources in the same scan, so this
carries none of the ``__internet__``/``GraphIntegrityViolation`` risk
documented in ``normalizers/s3.py``.

The closed ``RelationshipType`` vocabulary (blueprint §10) is REUSED as
is — no Azure-specific relationship type is invented. ``ATTACHED_TO``
means the same thing here as on the AWS side ("this compute resource is
governed by that network control"), which is exactly why the graph and
the relationship-aware rule DSL need no Azure-specific code.

Azure's VM->NSG association is indirect (VM -> NIC -> NSG, or
VM -> NIC -> subnet -> NSG). Resolving that chain is the COLLECTOR's
job (``resource_collectors/compute.py``); this normalizer receives the
already-resolved NSG ids, exactly as the EC2 normalizer receives
already-extracted security group ids.
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId


def normalize_virtual_machine(
    *,
    resource_id: str,
    name: str,
    location: str,
    vm_size: str | None,
    public_ip_address: str | None,
    managed_disk_encryption_enabled: bool | None,
    system_assigned_identity_enabled: bool,
    network_security_group_ids: tuple[str, ...],
    tags: Mapping[str, str],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    relationships = tuple(
        ResourceRelationship(
            target_resource_id=ResourceId(nsg_id),
            relationship_type=RelationshipType.ATTACHED_TO,
        )
        for nsg_id in network_security_group_ids
    )

    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type="azure_virtual_machine",
        cloud_provider=CloudProvider.AZURE,
        tenant_id=tenant_id,
        region=location,
        attributes={
            "name": name,
            "vm_size": vm_size,
            "public_ip_address": public_ip_address,
            # None when the OS disk's encryption settings were not
            # collected — distinct from False (explicitly unencrypted).
            "managed_disk_encryption_enabled": managed_disk_encryption_enabled,
            # The Azure analogue of an EC2 IAM instance profile: a
            # managed identity lets the VM obtain short-lived tokens
            # instead of carrying static credentials on disk.
            "system_assigned_identity_enabled": system_assigned_identity_enabled,
        },
        tags=dict(tags),
        relationships=relationships,
        collected_at=collected_at,
        account_id=account_id,
    )
