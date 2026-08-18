"""Azure RBAC collectors and normalizers (STEP 8C).

What these tests are really defending:

**Permission is not reachability.** Every RBAC edge must be
informational. If `azure_role_assignment --ALLOWS--> subscription` ever
became traversable, one subscription-scoped assignment would turn into
an attack-path edge to everything in the subscription — thousands of
fabricated paths from a single authorization record. That is asserted
directly, not left to review.

**Identity is the object id, never the display name.** ARM's
authorization API returns no display name, and none is invented.

**Inheritance is never claimed.** Azure's list API returns assignments
that apply at the queried scope *and* ones inherited from above,
without marking which is which. So no assignment is labelled inherited.

**One malformed record costs one record.** A missing id, a null
principal, an unparseable scope — each is skipped or nulled
individually, and the surrounding assignments survive.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from domain.attack_paths.classification import ResourceRole, is_traversable, role_of
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import TenantId
from infrastructure.cloud.azure.errors import (
    AzureCollectionError,
    AzurePermissionError,
)
from infrastructure.cloud.azure.normalizers.authorization import (
    normalize_principal,
    normalize_role_assignment,
    normalize_role_definition,
)
from infrastructure.cloud.azure.resource_collectors.authorization import (
    RoleAssignmentCollector,
    RoleDefinitionCollector,
)

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
CLOCK = lambda: NOW  # noqa: E731

SUB = "11111111-2222-3333-4444-555555555555"
DIRECTORY = "99999999-8888-7777-6666-555555555555"
SUBSCRIPTION_SCOPE = f"/subscriptions/{SUB}"
RG_SCOPE = f"{SUBSCRIPTION_SCOPE}/resourceGroups/prod-rg"

PRINCIPAL_A = "aaaaaaaa-0000-0000-0000-000000000001"
PRINCIPAL_B = "bbbbbbbb-0000-0000-0000-000000000002"

OWNER_DEF = (
    f"/subscriptions/{SUB}/providers/Microsoft.Authorization"
    "/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
)
READER_DEF = (
    f"/subscriptions/{SUB}/providers/Microsoft.Authorization"
    "/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
)
ASSIGNMENT_A = f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleAssignments/ra-1"
ASSIGNMENT_B = f"{RG_SCOPE}/providers/Microsoft.Authorization/roleAssignments/ra-2"


# ---------------------------------------------------------------------
# Fakes — modelled on the azure-mgmt-authorization response shapes
# ---------------------------------------------------------------------


class Obj:
    """Attribute bag standing in for an Azure SDK model object."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def assignment(
    *,
    id=ASSIGNMENT_A,
    principal_id=PRINCIPAL_A,
    principal_type="ServicePrincipal",
    role_definition_id=OWNER_DEF,
    scope=SUBSCRIPTION_SCOPE,
    principal_tenant_id=DIRECTORY,
):
    return Obj(
        id=id,
        principal_id=principal_id,
        principal_type=principal_type,
        role_definition_id=role_definition_id,
        scope=scope,
        principal_tenant_id=principal_tenant_id,
    )


def permission(actions=(), not_actions=(), data_actions=(), not_data_actions=()):
    return Obj(
        actions=list(actions),
        not_actions=list(not_actions),
        data_actions=list(data_actions),
        not_data_actions=list(not_data_actions),
    )


def definition(
    *,
    id=OWNER_DEF,
    role_name="Owner",
    role_type="BuiltInRole",
    permissions=None,
    assignable_scopes=(SUBSCRIPTION_SCOPE,),
    description="Grants full access.",
):
    return Obj(
        id=id,
        role_name=role_name,
        role_type=role_type,
        permissions=permissions if permissions is not None else [permission(actions=["*"])],
        assignable_scopes=list(assignable_scopes),
        description=description,
    )


class FakeAuthorizationClient:
    def __init__(self, *, assignments=(), definitions=(), error=None):
        self._assignments = list(assignments)
        self._definitions = list(definitions)
        self._error = error
        outer = self

        class _Assignments:
            def list_for_subscription(self):
                if outer._error is not None:
                    raise outer._error
                return iter(outer._assignments)

        class _Definitions:
            def list(self, scope):
                outer.definition_scope = scope
                if outer._error is not None:
                    raise outer._error
                return iter(outer._definitions)

        self.role_assignments = _Assignments()
        self.role_definitions = _Definitions()


class FakeClients:
    def __init__(self, authorization):
        self.subscription_id = SUB
        self.authorization = authorization


def assignment_collector(**kwargs):
    return RoleAssignmentCollector(
        clients=FakeClients(FakeAuthorizationClient(**kwargs)),
        tenant_id=TENANT,
        clock=CLOCK,
        account_id=SUB,
    )


def definition_collector(**kwargs):
    return RoleDefinitionCollector(
        clients=FakeClients(FakeAuthorizationClient(**kwargs)),
        tenant_id=TENANT,
        clock=CLOCK,
        account_id=SUB,
    )


def by_type(resources, resource_type):
    return [r for r in resources if r.resource_type == resource_type]


# ---------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------


class TestRoleDefinitionCollector:
    def test_a_role_definition_is_collected(self) -> None:
        resource = definition_collector(definitions=[definition()]).collect()[0]
        assert resource.resource_type == "azure_role_definition"
        assert str(resource.resource_id) == OWNER_DEF
        assert resource.cloud_provider is CloudProvider.AZURE
        assert resource.account_id == SUB

    def test_it_is_listed_at_the_subscription_scope(self) -> None:
        client = FakeAuthorizationClient(definitions=[definition()])
        RoleDefinitionCollector(
            clients=FakeClients(client), tenant_id=TENANT, clock=CLOCK
        ).collect()
        assert client.definition_scope == SUBSCRIPTION_SCOPE

    def test_privilege_is_read_from_actions_not_from_the_name(self) -> None:
        # The whole reason the rule does not test `role_name == "Owner"`.
        harmless = definition(
            role_name="Owner", permissions=[permission(actions=["Microsoft.Storage/*/read"])]
        )
        resource = definition_collector(definitions=[harmless]).collect()[0]
        assert resource.attributes["role_name"] == "Owner"
        assert resource.attributes["grants_all_actions"] is False

    def test_a_custom_role_with_wildcard_actions_is_recognized(self) -> None:
        powerful = definition(
            id=READER_DEF,
            role_name="Team Helper",
            role_type="CustomRole",
            permissions=[permission(actions=["*"])],
        )
        resource = definition_collector(definitions=[powerful]).collect()[0]
        assert resource.attributes["grants_all_actions"] is True
        assert resource.attributes["is_built_in"] is False

    def test_a_scoped_wildcard_is_not_treated_as_unrestricted(self) -> None:
        # `Microsoft.Storage/*` is broad but bounded. Treating it as
        # unrestricted would fire the rule on every storage-admin role.
        scoped = definition(permissions=[permission(actions=["Microsoft.Storage/*"])])
        resource = definition_collector(definitions=[scoped]).collect()[0]
        assert resource.attributes["grants_all_actions"] is False

    def test_actions_are_unioned_across_permission_blocks_and_sorted(self) -> None:
        multi = definition(
            permissions=[
                permission(actions=["b/read"], not_actions=["z/write"]),
                permission(actions=["a/read", "b/read"]),
            ]
        )
        resource = definition_collector(definitions=[multi]).collect()[0]
        assert resource.attributes["actions"] == ["a/read", "b/read"]
        assert resource.attributes["not_actions"] == ["z/write"]

    def test_data_actions_are_tracked_separately(self) -> None:
        # Data-plane `*` reads blob and key content, which control-plane
        # `*` alone does not. Conflating them would misreport both.
        data = definition(
            permissions=[permission(actions=["a/read"], data_actions=["*"])]
        )
        resource = definition_collector(definitions=[data]).collect()[0]
        assert resource.attributes["grants_all_actions"] is False
        assert resource.attributes["grants_all_data_actions"] is True

    def test_an_unknown_role_type_yields_none_not_false(self) -> None:
        # "We do not know whether this role is built in" is not "it is
        # custom".
        resource = definition_collector(
            definitions=[definition(role_type=None)]
        ).collect()[0]
        assert resource.attributes["is_built_in"] is None

    def test_a_definition_without_an_id_is_skipped(self) -> None:
        resources = definition_collector(
            definitions=[definition(id=None), definition(id=READER_DEF)]
        ).collect()
        assert [str(r.resource_id) for r in resources] == [READER_DEF]

    def test_duplicate_definitions_collapse_to_one(self) -> None:
        resources = definition_collector(
            definitions=[definition(), definition()]
        ).collect()
        assert len(resources) == 1

    def test_an_empty_subscription_returns_an_empty_tuple(self) -> None:
        assert definition_collector(definitions=[]).collect() == ()

    def test_a_definition_emits_no_relationships(self) -> None:
        # The assignment is the hub and owns every edge. A definition
        # pointing back would duplicate the same fact in two directions.
        assert definition_collector(definitions=[definition()]).collect()[0].relationships == ()


# ---------------------------------------------------------------------
# Role assignments
# ---------------------------------------------------------------------


class TestRoleAssignmentCollector:
    def test_an_assignment_is_collected_with_its_explicit_ids(self) -> None:
        resources = assignment_collector(assignments=[assignment()]).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert str(record.resource_id) == ASSIGNMENT_A
        assert record.attributes["principal_id"] == PRINCIPAL_A
        assert record.attributes["role_definition_id"] == OWNER_DEF
        assert record.attributes["scope"] == SUBSCRIPTION_SCOPE

    def test_the_scope_is_classified(self) -> None:
        resources = assignment_collector(assignments=[assignment()]).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert record.attributes["scope_type"] == "subscription"
        assert record.attributes["is_subscription_scope"] is True
        assert record.attributes["scope_is_parsed"] is True

    def test_a_resource_group_scope_is_not_a_subscription_scope(self) -> None:
        resources = assignment_collector(
            assignments=[assignment(id=ASSIGNMENT_B, scope=RG_SCOPE)]
        ).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert record.attributes["is_subscription_scope"] is False
        assert record.attributes["scope_resource_group"] == "prod-rg"

    def test_inheritance_is_never_claimed(self) -> None:
        # Azure's list API returns assignments applying at the scope AND
        # inherited ones, without marking which. Labelling any of them
        # inherited would be an invention.
        resources = assignment_collector(assignments=[assignment()]).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert record.attributes["inheritance_known"] is False

    def test_three_edges_are_emitted_from_explicit_fields(self) -> None:
        resources = assignment_collector(assignments=[assignment()]).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert {
            (str(r.target_resource_id), r.relationship_type) for r in record.relationships
        } == {
            (PRINCIPAL_A, RelationshipType.ATTACHED_TO),
            (OWNER_DEF, RelationshipType.ATTACHED_TO),
            (SUBSCRIPTION_SCOPE, RelationshipType.ALLOWS),
        }

    def test_every_edge_names_the_azure_field_it_came_from(self) -> None:
        resources = assignment_collector(assignments=[assignment()]).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        fields = {r.evidence["source_field"] for r in record.relationships}
        assert fields == {
            "roleAssignments.properties.principalId",
            "roleAssignments.properties.roleDefinitionId",
            "roleAssignments.properties.scope",
        }

    def test_a_missing_principal_produces_no_principal_edge(self) -> None:
        resources = assignment_collector(
            assignments=[assignment(principal_id=None)]
        ).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert len(record.relationships) == 2
        assert by_type(resources, "azure_principal") == []

    def test_a_blank_principal_is_treated_as_missing(self) -> None:
        # `""` would otherwise become a graph node whose id is empty.
        resources = assignment_collector(
            assignments=[assignment(principal_id="   ")]
        ).collect()
        assert by_type(resources, "azure_principal") == []

    def test_an_assignment_without_an_id_is_skipped(self) -> None:
        resources = assignment_collector(
            assignments=[assignment(id=None), assignment(id=ASSIGNMENT_B)]
        ).collect()
        assert [str(r.resource_id) for r in by_type(resources, "azure_role_assignment")] == [
            ASSIGNMENT_B
        ]

    def test_a_malformed_scope_is_recorded_as_unparsed_not_guessed(self) -> None:
        resources = assignment_collector(
            assignments=[assignment(scope="not-an-azure-scope")]
        ).collect()
        record = by_type(resources, "azure_role_assignment")[0]
        assert record.attributes["scope_is_parsed"] is False
        assert record.attributes["scope_type"] == "unknown"
        assert record.attributes["is_subscription_scope"] is False

    def test_one_malformed_assignment_does_not_cost_the_others(self) -> None:
        resources = assignment_collector(
            assignments=[
                assignment(id=None),
                assignment(scope=None, id=ASSIGNMENT_B),
                assignment(),
            ]
        ).collect()
        assert len(by_type(resources, "azure_role_assignment")) == 2

    def test_duplicate_assignments_collapse_to_one(self) -> None:
        resources = assignment_collector(
            assignments=[assignment(), assignment()]
        ).collect()
        assert len(by_type(resources, "azure_role_assignment")) == 1

    def test_an_empty_subscription_returns_an_empty_tuple(self) -> None:
        assert assignment_collector(assignments=[]).collect() == ()

    def test_collection_is_deterministic(self) -> None:
        first = assignment_collector(
            assignments=[assignment(), assignment(id=ASSIGNMENT_B, principal_id=PRINCIPAL_B)]
        ).collect()
        second = assignment_collector(
            assignments=[assignment(), assignment(id=ASSIGNMENT_B, principal_id=PRINCIPAL_B)]
        ).collect()
        assert first == second


class TestPrincipalDerivation:
    def test_a_principal_is_derived_from_the_assignment(self) -> None:
        resources = assignment_collector(assignments=[assignment()]).collect()
        principal = by_type(resources, "azure_principal")[0]
        assert str(principal.resource_id) == PRINCIPAL_A
        assert principal.attributes["principal_type"] == "ServicePrincipal"
        assert principal.attributes["directory_tenant_id"] == DIRECTORY

    def test_no_display_name_is_invented(self) -> None:
        # ARM's authorization API returns none. Identity is the object
        # id, and a guessed label is worse than no label.
        resources = assignment_collector(assignments=[assignment()]).collect()
        principal = by_type(resources, "azure_principal")[0]
        assert "display_name" not in principal.attributes

    def test_a_principal_is_marked_as_not_directory_enumerated(self) -> None:
        # We learned it exists because something was assigned to it, not
        # by listing the directory. Microsoft Graph would be needed for
        # the latter, and a rule must be able to tell them apart.
        resources = assignment_collector(assignments=[assignment()]).collect()
        assert by_type(resources, "azure_principal")[0].attributes[
            "is_directory_enumerated"
        ] is False

    def test_one_principal_with_several_assignments_yields_one_resource(self) -> None:
        resources = assignment_collector(
            assignments=[
                assignment(),
                assignment(id=ASSIGNMENT_B, scope=RG_SCOPE, role_definition_id=READER_DEF),
            ]
        ).collect()
        assert len(by_type(resources, "azure_principal")) == 1
        assert len(by_type(resources, "azure_role_assignment")) == 2

    def test_principals_are_emitted_in_sorted_order(self) -> None:
        resources = assignment_collector(
            assignments=[
                assignment(id=ASSIGNMENT_B, principal_id=PRINCIPAL_B),
                assignment(principal_id=PRINCIPAL_A),
            ]
        ).collect()
        ids = [str(r.resource_id) for r in by_type(resources, "azure_principal")]
        assert ids == sorted(ids)

    @pytest.mark.parametrize(
        "principal_type", ["User", "Group", "ServicePrincipal", "ForeignGroup", "Device"]
    )
    def test_every_documented_principal_type_is_carried_through(
        self, principal_type
    ) -> None:
        resources = assignment_collector(
            assignments=[assignment(principal_type=principal_type)]
        ).collect()
        principal = by_type(resources, "azure_principal")[0]
        assert principal.attributes["principal_type"] == principal_type
        assert principal.attributes["principal_type_is_known"] is True

    def test_an_unrecognized_principal_type_is_preserved_and_flagged(self) -> None:
        # Preserved verbatim rather than mapped onto the nearest known
        # kind, and flagged so a rule can refuse to reason about it.
        resources = assignment_collector(
            assignments=[assignment(principal_type="SomethingNew")]
        ).collect()
        principal = by_type(resources, "azure_principal")[0]
        assert principal.attributes["principal_type"] == "SomethingNew"
        assert principal.attributes["principal_type_is_known"] is False

    def test_managed_identity_is_not_claimed_as_a_distinct_type(self) -> None:
        # Azure reports managed identities as ServicePrincipal and gives
        # no field that separates them. Synthesizing a ManagedIdentity
        # type here would be an invention — see the audit §5.
        from infrastructure.cloud.azure.normalizers.authorization import (
            KNOWN_PRINCIPAL_TYPES,
        )

        assert "ManagedIdentity" not in KNOWN_PRINCIPAL_TYPES


class TestSubscriptionScopeNode:
    def test_the_subscription_is_emitted_when_it_is_an_assignment_scope(self) -> None:
        # Without it the ALLOWS edge points at a node nothing
        # enumerated, and "scoped to the subscription we scanned" cannot
        # be told from "scoped to something we never saw".
        resources = assignment_collector(assignments=[assignment()]).collect()
        subscription = by_type(resources, "azure_subscription")[0]
        assert str(subscription.resource_id) == SUBSCRIPTION_SCOPE
        assert subscription.attributes["subscription_id"] == SUB

    def test_it_is_not_emitted_when_nothing_is_scoped_to_it(self) -> None:
        resources = assignment_collector(
            assignments=[assignment(scope=RG_SCOPE)]
        ).collect()
        assert by_type(resources, "azure_subscription") == []

    def test_a_differently_cased_subscription_scope_still_matches(self) -> None:
        # GUIDs are case-insensitive; the scope must still resolve to
        # the subscription being scanned.
        resources = assignment_collector(
            assignments=[assignment(scope=f"/subscriptions/{SUB.upper()}")]
        ).collect()
        assert len(by_type(resources, "azure_subscription")) == 1

    def test_a_different_subscription_does_not_create_the_node(self) -> None:
        other = "/subscriptions/00000000-0000-0000-0000-000000000000"
        resources = assignment_collector(assignments=[assignment(scope=other)]).collect()
        assert by_type(resources, "azure_subscription") == []


# ---------------------------------------------------------------------
# Error handling — the existing Azure taxonomy, reused
# ---------------------------------------------------------------------


class TestCollectorErrors:
    def test_access_denied_becomes_a_collection_error_with_a_permission_cause(self) -> None:
        # 403 on Microsoft.Authorization/*/read is the common case, and
        # AzureCollector skips just this service rather than failing the
        # whole subscription scan.
        error = type("HttpResponseError", (Exception,), {})("forbidden")
        error.status_code = 403

        with pytest.raises(AzureCollectionError) as exc_info:
            assignment_collector(error=error).collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)

    def test_role_definition_access_denied_is_isolated_the_same_way(self) -> None:
        error = type("HttpResponseError", (Exception,), {})("forbidden")
        error.status_code = 403
        with pytest.raises(AzureCollectionError) as exc_info:
            definition_collector(error=error).collect()
        assert isinstance(exc_info.value.__cause__, AzurePermissionError)

    def test_an_sdk_failure_never_escapes_as_a_raw_exception(self) -> None:
        with pytest.raises(AzureCollectionError):
            assignment_collector(error=RuntimeError("boom")).collect()


# ---------------------------------------------------------------------
# Permission is not reachability
# ---------------------------------------------------------------------


class TestRbacIsNotAnAttackPath:
    """The load-bearing constraint of STEP 8C."""

    def _edges(self):
        from application.graph.build_resource_graph import BuildResourceGraph

        resources = assignment_collector(assignments=[assignment()]).collect()
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
        return graph.edges

    def test_no_rbac_edge_is_traversable(self) -> None:
        # If this ever passes as True, one subscription-scoped
        # assignment becomes an attack-path edge to everything in the
        # subscription.
        assert not [edge for edge in self._edges() if is_traversable(edge)]

    def test_the_scope_grant_uses_allows_not_accesses(self) -> None:
        # ACCESSES is traversable and means "can reach". A role
        # assignment proves permission, not reachability.
        scope_edges = [
            e for e in self._edges() if str(e.target_id) == SUBSCRIPTION_SCOPE
        ]
        assert [e.relationship_type for e in scope_edges] == [RelationshipType.ALLOWS]

    def test_a_principal_is_classified_as_an_identity(self) -> None:
        from application.graph.build_resource_graph import BuildResourceGraph

        resources = assignment_collector(assignments=[assignment()]).collect()
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
        node = next(n for n in graph.nodes if str(n.resource_id) == PRINCIPAL_A)
        assert role_of(node) is ResourceRole.IDENTITY

    def test_authorization_records_are_not_targets(self) -> None:
        from application.graph.build_resource_graph import BuildResourceGraph

        resources = assignment_collector(assignments=[assignment()]).collect()
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
        for resource_id in (ASSIGNMENT_A, SUBSCRIPTION_SCOPE):
            node = next(n for n in graph.nodes if str(n.resource_id) == resource_id)
            assert role_of(node) is ResourceRole.OTHER


# ---------------------------------------------------------------------
# Normalizers in isolation
# ---------------------------------------------------------------------


class TestNormalizersAreProviderNeutral:
    def test_rbac_resources_carry_no_region(self) -> None:
        # RBAC is not regional: a scope spans regions. `None` states
        # that rather than inventing one.
        record = normalize_role_assignment(
            role_assignment_id=ASSIGNMENT_A,
            principal_id=PRINCIPAL_A,
            principal_type="User",
            role_definition_id=OWNER_DEF,
            scope=SUBSCRIPTION_SCOPE,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert record.region is None

    def test_a_principal_normalizes_without_a_type(self) -> None:
        principal = normalize_principal(
            principal_id=PRINCIPAL_A,
            principal_type=None,
            directory_tenant_id=None,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert principal.attributes["principal_type"] is None
        assert principal.attributes["principal_type_is_known"] is False

    def test_a_role_definition_with_no_permissions_grants_nothing(self) -> None:
        record = normalize_role_definition(
            role_definition_id=READER_DEF,
            role_name="Empty",
            role_type="CustomRole",
            permissions=None,
            assignable_scopes=None,
            description=None,
            tenant_id=TENANT,
            collected_at=NOW,
        )
        assert record.attributes["actions"] == []
        assert record.attributes["grants_all_actions"] is False
