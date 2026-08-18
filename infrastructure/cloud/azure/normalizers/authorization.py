"""Azure RBAC → ``NormalizedResource`` (STEP 8C).

Three resource types and the edges between them:

    azure_principal  <--ATTACHED_TO--  azure_role_assignment
                                              |
                                              +--ATTACHED_TO--> azure_role_definition
                                              |
                                              +--ALLOWS-------> scope

The role assignment is a **first-class node** rather than evidence
attached to the principal, and that is the load-bearing modelling
decision here. A principal typically holds several assignments, and
each one pairs *one* role with *one* scope. Flattened onto the
principal, "Owner at the subscription" and "Reader on one storage
account" become two role lists and two scope lists whose pairing is
lost — and that pairing is the entire security question. The hub node
keeps the pair intact and costs one node per assignment, which is what
Azure itself has.

**Permission is not reachability.** Every edge here is informational:
`ATTACHED_TO` and `ALLOWS` are both in
`domain/attack_paths/classification.py`'s informational set. `ACCESSES`
was available and was deliberately not used — it is traversable, and a
subscription-scoped assignment would then become an attack-path edge to
everything, fabricating movement out of an authorization record. RBAC
proves someone *may* act, not that anyone *can reach* anything.

**Nothing is inferred.** `principalId`, `principalType`,
`roleDefinitionId` and `scope` are all explicit fields Azure returns on
the assignment. Where a field is absent, the attribute is `None` and no
edge is emitted — an unverified privilege edge is worse than a missing
one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence

from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId
from infrastructure.cloud.azure.resource_ids import (
    AzureScopeType,
    parse_azure_resource_id,
)

#: `principalType` values Azure documents on a role assignment. Kept as
#: an explicit set so an unrecognized value is preserved verbatim and
#: flagged, rather than silently mapped onto the nearest known kind.
#:
#: `ManagedIdentity` is deliberately ABSENT. Azure reports managed
#: identities as `ServicePrincipal`; there is no RBAC field that
#: separates them. Claiming the distinction from this data would be an
#: invention — see docs/audits/azure-identity-current-state.md §5.
KNOWN_PRINCIPAL_TYPES = frozenset(
    {"User", "Group", "ServicePrincipal", "ForeignGroup", "Device"}
)


def _resource(
    *,
    resource_id: str,
    resource_type: str,
    attributes: dict[str, Any],
    relationships: tuple[ResourceRelationship, ...],
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None,
) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AZURE,
        tenant_id=tenant_id,
        # RBAC is not a regional concept: a role assignment applies at a
        # scope, and scopes span regions. `None` states that rather than
        # inventing a region for it.
        region=None,
        attributes=attributes,
        tags={},
        relationships=relationships,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------


def normalize_principal(
    *,
    principal_id: str,
    principal_type: str | None,
    directory_tenant_id: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One Entra principal, as known from RBAC alone.

    The identity is ``principal_id`` — the Entra object id — and nothing
    else. No display name is collected, because ARM's authorization API
    does not return one and reading it would need Microsoft Graph. A
    principal with no display name is honest; one with a display name
    guessed from a role assignment's other fields would not be.

    ``is_directory_enumerated`` is ``False`` for every principal this
    module produces, and that is the point: we learned this principal
    exists *because something was assigned to it*, not because we listed
    the directory. A rule must be able to tell that apart from a fully
    enumerated principal, and one boolean is cheaper than discovering
    later that it cannot.
    """

    known_type = principal_type in KNOWN_PRINCIPAL_TYPES if principal_type else False

    return _resource(
        resource_id=principal_id,
        resource_type="azure_principal",
        attributes={
            # The Entra object id, restated as an attribute so a rule can
            # read it without parsing the resource id.
            "principal_id": principal_id,
            # Verbatim. An unrecognized value is preserved, not mapped.
            "principal_type": principal_type,
            # False for an unrecognized or missing type, so a rule can
            # refuse to reason about a principal kind we do not know.
            "principal_type_is_known": known_type,
            # The Entra directory (Azure AD tenant), NOT ComplianceIQ's
            # own TenantId. The two are never conflated.
            "directory_tenant_id": directory_tenant_id,
            # Known from an assignment, not from a directory listing.
            # Microsoft Graph would be needed to set this True.
            "is_directory_enumerated": False,
        },
        relationships=(),
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Role definition
# ---------------------------------------------------------------------


def _permission_actions(permissions: Sequence[Mapping[str, Any]] | None) -> dict[str, list[str]]:
    """Flatten Azure's permission blocks into four sorted action lists.

    Azure returns permissions as a list of blocks, each with its own
    actions/notActions/dataActions/notDataActions. They are unioned
    because a role grants the union of its blocks, and sorted so two
    scans of an unchanged role produce an identical resource.

    The blocks themselves are not preserved. A role's *effective*
    permission is the union — no rule in this codebase needs to know
    which block an action came from, and keeping the raw structure would
    be exactly the large opaque payload the brief forbids.
    """

    actions: set[str] = set()
    not_actions: set[str] = set()
    data_actions: set[str] = set()
    not_data_actions: set[str] = set()

    for block in permissions or ():
        actions.update(block.get("actions") or ())
        not_actions.update(block.get("not_actions") or ())
        data_actions.update(block.get("data_actions") or ())
        not_data_actions.update(block.get("not_data_actions") or ())

    return {
        "actions": sorted(actions),
        "not_actions": sorted(not_actions),
        "data_actions": sorted(data_actions),
        "not_data_actions": sorted(not_data_actions),
    }


def _grants_all_actions(actions: Sequence[str]) -> bool:
    """Whether the role grants the unrestricted control-plane wildcard.

    Exactly ``*`` — not ``Microsoft.Storage/*``, which is broad but
    bounded. This is the property that actually distinguishes Owner and
    Contributor from every scoped built-in role, and it is read from the
    permissions Azure returned rather than from the role's name. A rule
    written as ``role_name == "Owner"`` would miss a custom role with
    identical power and would fire on a harmless role someone happened
    to name "Owner".
    """

    return "*" in actions


def normalize_role_definition(
    *,
    role_definition_id: str,
    role_name: str | None,
    role_type: str | None,
    permissions: Sequence[Mapping[str, Any]] | None,
    assignable_scopes: Sequence[str] | None,
    description: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One RBAC role definition.

    Only fields with a consumer are kept. ``description`` is retained
    because it is what a finding's evidence shows a human reading the
    report; ``createdOn``/``updatedBy``/``createdBy`` and the raw
    permission blocks are dropped, because nothing reasons about them.
    """

    action_sets = _permission_actions(permissions)
    grants_all = _grants_all_actions(action_sets["actions"])

    return _resource(
        resource_id=role_definition_id,
        resource_type="azure_role_definition",
        attributes={
            "role_definition_id": role_definition_id,
            "role_name": role_name,
            # Azure's own value: "BuiltInRole" or "CustomRole".
            "role_type": role_type,
            # None (not False) when the API did not say — "we do not
            # know whether this role is built in" is not "it is custom".
            "is_built_in": (
                None if role_type is None else str(role_type).lower() == "builtinrole"
            ),
            "description": description,
            **action_sets,
            # Derived, ALONGSIDE the actions above rather than instead
            # of them, so a rule that disagrees can read what we saw.
            "grants_all_actions": grants_all,
            # `*` on the DATA plane is a distinct and separately
            # dangerous grant: it reads blob and key content, which
            # control-plane `*` alone does not.
            "grants_all_data_actions": _grants_all_actions(action_sets["data_actions"]),
            "assignable_scopes": sorted(assignable_scopes or ()),
        },
        relationships=(),
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Role assignment
# ---------------------------------------------------------------------


def normalize_role_assignment(
    *,
    role_assignment_id: str,
    principal_id: str | None,
    principal_type: str | None,
    role_definition_id: str | None,
    scope: str | None,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """One RBAC role assignment — the hub of the chain.

    Emits up to three edges, each guarded by the presence of the AWS-
    equivalent "did the API actually name this" check. A missing
    ``principalId`` produces no principal edge rather than an edge to
    an empty id.
    """

    parsed_scope = parse_azure_resource_id(scope)
    relationships: list[ResourceRelationship] = []

    if principal_id:
        relationships.append(
            ResourceRelationship(
                target_resource_id=ResourceId(principal_id),
                relationship_type=RelationshipType.ATTACHED_TO,
                evidence={
                    "source_field": "roleAssignments.properties.principalId",
                    "principal_type": principal_type,
                },
                confidence="high",
            )
        )

    if role_definition_id:
        relationships.append(
            ResourceRelationship(
                target_resource_id=ResourceId(role_definition_id),
                relationship_type=RelationshipType.ATTACHED_TO,
                evidence={
                    "source_field": "roleAssignments.properties.roleDefinitionId"
                },
                confidence="high",
            )
        )

    if scope:
        relationships.append(
            ResourceRelationship(
                target_resource_id=ResourceId(scope),
                # ALLOWS, not ACCESSES. This grants permission at the
                # scope; it does not establish that anyone can reach
                # anything. ALLOWS is informational, ACCESSES is
                # traversable, and choosing the latter here would turn
                # every RBAC record into a fabricated attack path.
                relationship_type=RelationshipType.ALLOWS,
                evidence={
                    "source_field": "roleAssignments.properties.scope",
                    "scope_type": parsed_scope.scope_type.value,
                },
                confidence="high",
            )
        )

    return _resource(
        resource_id=role_assignment_id,
        resource_type="azure_role_assignment",
        attributes={
            "role_assignment_id": role_assignment_id,
            "principal_id": principal_id,
            "principal_type": principal_type,
            "role_definition_id": role_definition_id,
            "scope": scope,
            "scope_type": parsed_scope.scope_type.value,
            # False when the scope string did not match a documented
            # shape. A rule must be able to refuse to reason about a
            # scope we could not place — an unrecognized scope defaulted
            # to "resource" would understate a management-group grant.
            "scope_is_parsed": parsed_scope.is_parsed,
            "scope_subscription_id": parsed_scope.subscription_id,
            "scope_resource_group": parsed_scope.resource_group,
            "scope_management_group": parsed_scope.management_group,
            # Convenience booleans for rule authors, derived from the
            # parse rather than from string matching in YAML.
            "is_subscription_scope": (
                parsed_scope.scope_type is AzureScopeType.SUBSCRIPTION
            ),
            "is_management_group_scope": (
                parsed_scope.scope_type is AzureScopeType.MANAGEMENT_GROUP
            ),
            # Azure's list API returns assignments applying AT the
            # queried scope and inherited ones, but the response does
            # not mark which is which. We therefore never claim
            # inheritance — see the architecture doc's scope section.
            "inheritance_known": False,
        },
        relationships=tuple(relationships),
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


# ---------------------------------------------------------------------
# Subscription (scope target)
# ---------------------------------------------------------------------


def normalize_subscription(
    *,
    subscription_scope: str,
    subscription_id: str,
    tenant_id: TenantId,
    collected_at: datetime,
    account_id: str | None = None,
) -> NormalizedResource:
    """The subscription itself, as an assignment scope target.

    Collected for exactly one reason: without it, every
    subscription-scoped assignment's ``ALLOWS`` edge points at a node
    nothing enumerated, and the graph cannot distinguish "scoped to the
    subscription we scanned" from "scoped to something we never saw".

    Deliberately thin. This is not a subscription collector — it carries
    identity and nothing else, because nothing yet reasons about
    subscription properties.
    """

    return _resource(
        resource_id=subscription_scope,
        resource_type="azure_subscription",
        attributes={
            "subscription_id": subscription_id,
            "scope_type": AzureScopeType.SUBSCRIPTION.value,
        },
        relationships=(),
        tenant_id=tenant_id,
        collected_at=collected_at,
        account_id=account_id,
    )


__all__ = [
    "KNOWN_PRINCIPAL_TYPES",
    "normalize_principal",
    "normalize_role_assignment",
    "normalize_role_definition",
    "normalize_subscription",
]
