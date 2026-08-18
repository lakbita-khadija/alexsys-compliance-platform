"""Azure resource ID and RBAC scope parsing (STEP 8C).

Two things carry the weight, and both are about refusing to guess.

**Scope classification is the security question.** An RBAC role
assignment's `scope` is one of these strings, and whether it addresses a
management group, a subscription, a resource group or a single resource
is the difference between a catastrophic grant and a routine one. Every
shape gets a test, and so does every shape we cannot place.

**Case handling is per-component and deliberate.** Structural keywords
and GUIDs are case-insensitive because Azure demonstrably treats them
that way. Resource group names, provider namespaces and resource names
are preserved verbatim because we have no per-provider evidence that
they are interchangeable, and silently merging two resources is worse
than reporting two a human can reconcile.
"""

from __future__ import annotations

import pytest

from infrastructure.cloud.azure.resource_ids import (
    AzureScopeType,
    classify_scope,
    parse_azure_resource_id,
    subscription_scope_id,
)

SUB = "11111111-2222-3333-4444-555555555555"
MG = "/providers/Microsoft.Management/managementGroups/corp-root"
SUBSCRIPTION = f"/subscriptions/{SUB}"
RG = f"{SUBSCRIPTION}/resourceGroups/prod-rg"
STORAGE = f"{RG}/providers/Microsoft.Storage/storageAccounts/prodstore"
SQL_DB = (
    f"{RG}/providers/Microsoft.Sql/servers/prod-sql/databases/orders"
)


class TestScopeClassification:
    @pytest.mark.parametrize(
        "resource_id, expected",
        [
            (MG, AzureScopeType.MANAGEMENT_GROUP),
            (SUBSCRIPTION, AzureScopeType.SUBSCRIPTION),
            (RG, AzureScopeType.RESOURCE_GROUP),
            (STORAGE, AzureScopeType.RESOURCE),
            (SQL_DB, AzureScopeType.RESOURCE),
        ],
    )
    def test_each_documented_shape_is_classified(self, resource_id, expected) -> None:
        assert classify_scope(resource_id) is expected

    def test_a_trailing_slash_does_not_change_the_scope(self) -> None:
        assert classify_scope(SUBSCRIPTION + "/") is AzureScopeType.SUBSCRIPTION


class TestSubscriptionScope:
    def test_the_subscription_guid_is_extracted(self) -> None:
        parsed = parse_azure_resource_id(SUBSCRIPTION)
        assert parsed.subscription_id == SUB
        assert parsed.is_subscription_scope is True
        assert parsed.is_parsed is True

    def test_a_subscription_has_no_resource_group_or_name(self) -> None:
        parsed = parse_azure_resource_id(SUBSCRIPTION)
        assert parsed.resource_group is None
        assert parsed.resource_name is None
        assert parsed.provider_namespace is None

    def test_the_canonical_id_is_exactly_what_azure_returned(self) -> None:
        # Never a reconstruction: rebuilding it would normalize casing
        # and drop any segment this parser does not model, and the id is
        # the identity.
        weird = f"/Subscriptions/{SUB.upper()}"
        assert parse_azure_resource_id(weird).canonical_id == weird

    def test_the_helper_builds_the_documented_form(self) -> None:
        assert subscription_scope_id(SUB.upper()) == f"/subscriptions/{SUB}"


class TestResourceGroupScope:
    def test_the_resource_group_name_is_extracted(self) -> None:
        parsed = parse_azure_resource_id(RG)
        assert parsed.resource_group == "prod-rg"
        assert parsed.subscription_id == SUB
        assert parsed.scope_type is AzureScopeType.RESOURCE_GROUP

    def test_a_resource_group_is_not_a_subscription_scope(self) -> None:
        assert parse_azure_resource_id(RG).is_subscription_scope is False


class TestResourceScope:
    def test_provider_type_and_name_are_extracted(self) -> None:
        parsed = parse_azure_resource_id(STORAGE)
        assert parsed.provider_namespace == "Microsoft.Storage"
        assert parsed.resource_type == "storageAccounts"
        assert parsed.resource_name == "prodstore"
        assert parsed.resource_group == "prod-rg"

    def test_a_nested_type_keeps_the_full_type_path_and_leaf_name(self) -> None:
        # servers/prod-sql/databases/orders — the database is the
        # resource, and the type path records that it lives under a
        # server rather than flattening to "databases".
        parsed = parse_azure_resource_id(SQL_DB)
        assert parsed.resource_type == "servers/databases"
        assert parsed.resource_name == "orders"


class TestCaseHandling:
    """Per-component, and each choice is asserted rather than assumed."""

    def test_structural_keywords_are_matched_case_insensitively(self) -> None:
        # ARM returns `resourceGroups`; some services echo
        # `resourcegroups`. Both name the same thing.
        variants = [
            f"/subscriptions/{SUB}/resourceGroups/prod-rg",
            f"/subscriptions/{SUB}/resourcegroups/prod-rg",
            f"/Subscriptions/{SUB}/RESOURCEGROUPS/prod-rg",
        ]
        for variant in variants:
            parsed = parse_azure_resource_id(variant)
            assert parsed.scope_type is AzureScopeType.RESOURCE_GROUP
            assert parsed.resource_group == "prod-rg"

    def test_subscription_guids_are_lowercased(self) -> None:
        # A GUID's hex digits are case-insensitive by definition, and
        # Azure returns them lowercased. Normalizing here means two
        # scopes differing only in GUID case compare equal.
        upper = f"/subscriptions/{SUB.upper()}"
        assert parse_azure_resource_id(upper).subscription_id == SUB

    def test_resource_group_names_are_preserved_verbatim(self) -> None:
        # NOT lowercased. Azure is case-preserving here, and we have no
        # evidence that would justify collapsing two spellings into one
        # resource.
        parsed = parse_azure_resource_id(f"/subscriptions/{SUB}/resourceGroups/Prod-RG")
        assert parsed.resource_group == "Prod-RG"

    def test_provider_namespace_and_resource_name_are_preserved_verbatim(self) -> None:
        parsed = parse_azure_resource_id(
            f"/subscriptions/{SUB}/resourceGroups/rg"
            "/providers/Microsoft.KeyVault/vaults/ProdVault"
        )
        assert parsed.provider_namespace == "Microsoft.KeyVault"
        assert parsed.resource_name == "ProdVault"

    def test_two_ids_differing_only_in_group_case_are_not_collapsed(self) -> None:
        # The deliberate consequence, stated as a test so nobody
        # "fixes" it into an equivalence we cannot demonstrate.
        a = parse_azure_resource_id(f"/subscriptions/{SUB}/resourceGroups/rg")
        b = parse_azure_resource_id(f"/subscriptions/{SUB}/resourceGroups/RG")
        assert a.resource_group != b.resource_group

    def test_management_group_names_are_preserved_verbatim(self) -> None:
        parsed = parse_azure_resource_id(
            "/providers/Microsoft.Management/managementGroups/Corp-Root"
        )
        assert parsed.management_group == "Corp-Root"


class TestManagementGroupScope:
    def test_the_management_group_name_is_extracted(self) -> None:
        parsed = parse_azure_resource_id(MG)
        assert parsed.scope_type is AzureScopeType.MANAGEMENT_GROUP
        assert parsed.management_group == "corp-root"

    def test_a_management_group_has_no_subscription(self) -> None:
        # It sits ABOVE subscriptions. Inventing one would misplace the
        # broadest grant Azure has.
        assert parse_azure_resource_id(MG).subscription_id is None


class TestMalformedIds:
    """Unparseable stays unparseable. Nothing raises, nothing guesses."""

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "   ",
            "not-an-azure-id",
            "/",
            "/subscriptions",
            "/resourceGroups/orphan",
            f"/subscriptions/{SUB}/somethingElse/x",
            # Odd tail after the provider: which segment is the name?
            # Guessing would put an invented identity in the graph.
            f"{RG}/providers/Microsoft.Sql/servers/prod-sql/databases",
        ],
    )
    def test_an_unrecognized_id_is_reported_as_unparsed(self, value) -> None:
        parsed = parse_azure_resource_id(value)
        assert parsed.is_parsed is False
        assert parsed.scope_type is AzureScopeType.UNKNOWN

    def test_parsing_never_raises(self) -> None:
        for value in (None, "", "///", "/subscriptions//"):
            parse_azure_resource_id(value)

    def test_the_original_string_survives_a_failed_parse(self) -> None:
        assert parse_azure_resource_id("garbage").canonical_id == "garbage"

    def test_partial_information_is_kept_when_the_tail_is_unrecognized(self) -> None:
        # We genuinely learned the subscription before the id stopped
        # making sense; discarding that would lose real evidence.
        parsed = parse_azure_resource_id(f"/subscriptions/{SUB}/somethingElse/x")
        assert parsed.is_parsed is False
        assert parsed.subscription_id == SUB

    def test_an_unknown_scope_is_never_defaulted_to_resource(self) -> None:
        # Defaulting to the most common case would understate a
        # management-group assignment, which is the broadest grant.
        assert classify_scope("mystery") is not AzureScopeType.RESOURCE
