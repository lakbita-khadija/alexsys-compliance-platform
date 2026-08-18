"""Azure RBAC in the graph and in a rule (STEP 8C).

Three concerns, in order of how badly getting them wrong would hurt:

**An unenumerated principal must never become a clean answer.** ARM's
authorization API returns a `principalId` for every assignment, but
nothing in this step lists the directory — so a principal is enumerated
only if some assignment named it. When a rule reasons about a principal
that was never enumerated, the answer is INDETERMINATE. Both
`relationship(...)` and `no_relationship(...)` are tested, because they
fail in opposite directions: the first would report a false PASS, the
second a fabricated violation.

**The graph must hold together.** No dangling edges, no duplicates, no
self-loops, a fingerprint that is stable across identical input and
independent of collector ordering, and one tenant and subscription
throughout.

**The rule must be provable in all three states.** PASS, FAIL and
INDETERMINATE fixtures, because a rule that cannot produce
INDETERMINATE is a rule that hides missing evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from application.graph.build_resource_graph import BuildResourceGraph
from application.rules.evaluate_rules import EvaluateRules
from domain.findings.models import FindingStatus
from domain.graph.validation import Severity as ValidationSeverity
from domain.graph.validation import graph_fingerprint, validate_graph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.rules.conditions import EvaluationResult, evaluate_condition
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, RuleId, TenantId
from domain.shared.unknown import UNKNOWN
from infrastructure.rules.yaml_rule_catalog import YamlRuleCatalog

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[3]

SUB = "11111111-2222-3333-4444-555555555555"
SUBSCRIPTION_SCOPE = f"/subscriptions/{SUB}"
RG_SCOPE = f"{SUBSCRIPTION_SCOPE}/resourceGroups/prod-rg"
PRINCIPAL = "aaaaaaaa-0000-0000-0000-000000000001"
OTHER_PRINCIPAL = "bbbbbbbb-0000-0000-0000-000000000002"
OWNER_DEF = f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/owner"
READER_DEF = f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleDefinitions/reader"
ASSIGNMENT = f"{SUBSCRIPTION_SCOPE}/providers/Microsoft.Authorization/roleAssignments/ra-1"

RULE = "azure-privileged-role-assigned-at-subscription-scope"


@pytest.fixture(scope="module")
def catalog():
    return YamlRuleCatalog(REPO_ROOT / "rules" / "azure")


def resource(rid, rtype, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AZURE,
        tenant_id=TENANT,
        region=None,
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=NOW,
        account_id=SUB,
    )


def rel(target, kind=RelationshipType.ATTACHED_TO):
    return ResourceRelationship(
        target_resource_id=ResourceId(target), relationship_type=kind
    )


def role_assignment(*, scope=SUBSCRIPTION_SCOPE, role=OWNER_DEF, principal=PRINCIPAL):
    relationships = []
    if principal:
        relationships.append(rel(principal))
    if role:
        relationships.append(rel(role))
    if scope:
        relationships.append(rel(scope, RelationshipType.ALLOWS))
    return resource(
        ASSIGNMENT,
        "azure_role_assignment",
        {
            "principal_id": principal,
            "role_definition_id": role,
            "scope": scope,
            "is_subscription_scope": scope == SUBSCRIPTION_SCOPE,
            "scope_is_parsed": scope is not None,
            "inheritance_known": False,
        },
        tuple(relationships),
    )


def role_definition(rid=OWNER_DEF, *, grants_all=True, name="Owner"):
    return resource(
        rid,
        "azure_role_definition",
        {
            "role_name": name,
            "grants_all_actions": grants_all,
            "actions": ["*"] if grants_all is True else ["Microsoft.Storage/*/read"],
        },
    )


def principal(rid=PRINCIPAL, ptype="ServicePrincipal"):
    return resource(
        rid,
        "azure_principal",
        {
            "principal_id": rid,
            "principal_type": ptype,
            "principal_type_is_known": True,
            "is_directory_enumerated": False,
        },
    )


def subscription():
    return resource(SUBSCRIPTION_SCOPE, "azure_subscription", {"subscription_id": SUB})


def evaluate(catalog, resources, rule_id=RULE):
    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    return EvaluateRules(catalog).evaluate(
        tenant_id=TENANT,
        resources=resources,
        detected_at=NOW,
        scan_id="scan-1",
        rule_ids=(RuleId(rule_id),),
        graph=graph,
    )


def status_of(catalog, resources, subject=ASSIGNMENT):
    findings = [f for f in evaluate(catalog, resources) if str(f.resource_id) == subject]
    assert len(findings) == 1, f"expected one finding for {subject}, got {len(findings)}"
    return findings[0]


# ---------------------------------------------------------------------
# The proof-of-consumption rule
# ---------------------------------------------------------------------


class TestPrivilegedSubscriptionScopeRule:
    def test_a_wildcard_role_at_subscription_scope_fails(self, catalog) -> None:
        resources = [role_assignment(), role_definition(), principal(), subscription()]
        finding = status_of(catalog, resources)
        assert finding.status is FindingStatus.FAIL
        assert finding.severity is Severity.HIGH

    def test_a_scoped_role_at_subscription_scope_passes(self, catalog) -> None:
        # The privilege half saves it: subscription-wide Reader is broad
        # visibility, not unrestricted control.
        resources = [
            role_assignment(role=READER_DEF),
            role_definition(READER_DEF, grants_all=False, name="Reader"),
            principal(),
            subscription(),
        ]
        assert status_of(catalog, resources).status is FindingStatus.PASS

    def test_a_wildcard_role_at_resource_group_scope_passes(self, catalog) -> None:
        # The scope half saves it: unrestricted within one resource
        # group is a normal delegation pattern.
        resources = [
            role_assignment(scope=RG_SCOPE),
            role_definition(),
            principal(),
            resource(RG_SCOPE, "azure_resource_group", {}),
        ]
        assert status_of(catalog, resources).status is FindingStatus.PASS

    def test_an_uncollected_role_definition_is_indeterminate(self, catalog) -> None:
        # The seam that matters most. If Microsoft.Authorization role
        # DEFINITION reads were denied while assignment reads succeeded,
        # we cannot know what the role grants — and "we could not check"
        # must not render as "this assignment is fine".
        resources = [role_assignment(), principal(), subscription()]
        assert status_of(catalog, resources).status is FindingStatus.INDETERMINATE

    def test_an_unreadable_permission_set_is_indeterminate(self, catalog) -> None:
        resources = [
            role_assignment(),
            role_definition(grants_all=UNKNOWN),
            principal(),
            subscription(),
        ]
        assert status_of(catalog, resources).status is FindingStatus.INDETERMINATE

    def test_privilege_is_not_inferred_from_the_role_name(self, catalog) -> None:
        # A role NAMED Owner that grants only scoped reads must not fire.
        resources = [
            role_assignment(),
            role_definition(grants_all=False, name="Owner"),
            principal(),
            subscription(),
        ]
        assert status_of(catalog, resources).status is FindingStatus.PASS

    def test_a_custom_role_with_wildcard_actions_still_fails(self, catalog) -> None:
        # The mirror case: the rule is about power, not about names.
        resources = [
            role_assignment(),
            role_definition(grants_all=True, name="Team Helper"),
            principal(),
            subscription(),
        ]
        assert status_of(catalog, resources).status is FindingStatus.FAIL

    def test_the_evidence_states_permission_not_reachability(self, catalog) -> None:
        resources = [role_assignment(), role_definition(), principal(), subscription()]
        narrative = status_of(catalog, resources).evidence.data.get("narrative", "")
        assert ASSIGNMENT in narrative
        # A true risk stated in a false sentence is still a false
        # positive: the finding must not claim confirmed access.
        assert "not confirmed access" in narrative

    def test_it_maps_to_an_identity_control(self, catalog) -> None:
        resources = [role_assignment(), role_definition(), principal(), subscription()]
        finding = status_of(catalog, resources)
        assert finding.framework == "iso_27001"
        assert finding.control_id == "A.8.2"

    def test_no_mapping_claims_verified(self) -> None:
        from domain.compliance.catalog import build_catalog
        from domain.rules.rule import MAPPING_VERIFIED

        rules: list = []
        for directory in sorted(d for d in (REPO_ROOT / "rules").iterdir() if d.is_dir()):
            rules.extend(YamlRuleCatalog(directory).load())
        entries = build_catalog(rules).entries_for_rule(RULE)
        assert entries
        assert MAPPING_VERIFIED not in {e.status for e in entries}


# ---------------------------------------------------------------------
# Unenumerated principal — both quantifiers
# ---------------------------------------------------------------------


class TestUnenumeratedPrincipal:
    """Missing enumeration is neither absence nor compliance.

    STEP 8A.1 proved this for AWS. These prove the same guarantee holds
    for an Entra GUID, which matches none of the graph builder's
    provider prefixes and therefore takes the `external_resource` path.
    """

    def _evaluate(self, condition, subject, resources):
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
        return evaluate_condition(
            condition,
            subject,
            graph=graph,
            resources_by_id={r.resource_id: r for r in resources},
        )

    PRIVILEGED_PRINCIPAL = {
        "relationship": "attached_to",
        "direction": "outgoing",
        "target_type": "azure_principal",
        "where": {"field": "principal_type", "operator": "equals", "value": "User"},
    }

    NO_PRINCIPAL = {
        "no_relationship": "attached_to",
        "direction": "outgoing",
        "target_type": "azure_principal",
        "requires_collected": "azure_principal",
    }

    def test_an_unenumerated_principal_becomes_an_external_node(self) -> None:
        resources = [role_assignment(), role_definition()]
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
        node = next(n for n in graph.nodes if str(n.resource_id) == PRINCIPAL)
        assert node.is_external
        # Not `azure_principal`: a GUID is not evidence of a type, and a
        # rule targeting azure_principal must not match a node nobody
        # enumerated.
        assert node.resource_type == "external_resource"
        assert node.source_collector == "relationship-inference"

    def test_relationship_over_an_unenumerated_principal_is_indeterminate(self) -> None:
        # Would otherwise be a false PASS: zero neighbours survive the
        # target_type filter, which is vacuously NOT_MATCHED.
        subject = role_assignment()
        result = self._evaluate(
            self.PRIVILEGED_PRINCIPAL, subject, [subject, role_definition()]
        )
        assert result is EvaluationResult.INDETERMINATE

    def test_no_relationship_over_an_unenumerated_principal_is_indeterminate(self) -> None:
        # The inverted failure: this would otherwise report "this
        # assignment has no principal", a fabricated violation. Another
        # principal IS enumerated, so the coverage guard passes and
        # cannot be what saves us here.
        subject = role_assignment()
        resources = [subject, role_definition(), principal(OTHER_PRINCIPAL)]
        assert self._evaluate(self.NO_PRINCIPAL, subject, resources) is (
            EvaluationResult.INDETERMINATE
        )

    def test_an_enumerated_principal_still_gives_a_determinate_answer(self) -> None:
        # The fix must not turn every clean result into INDETERMINATE.
        subject = role_assignment()
        resources = [subject, role_definition(), principal(ptype="User")]
        assert self._evaluate(self.PRIVILEGED_PRINCIPAL, subject, resources) is (
            EvaluationResult.MATCHED
        )

    def test_an_enumerated_principal_of_another_type_is_determinate(self) -> None:
        subject = role_assignment()
        resources = [subject, role_definition(), principal(ptype="Group")]
        assert self._evaluate(self.PRIVILEGED_PRINCIPAL, subject, resources) is (
            EvaluationResult.NOT_MATCHED
        )

    def test_a_genuine_absence_is_still_reported(self) -> None:
        # An assignment with no principal edge at all, while principals
        # exist elsewhere: a real absence, not a data gap.
        subject = role_assignment(principal=None)
        resources = [subject, role_definition(), principal(OTHER_PRINCIPAL)]
        assert self._evaluate(self.NO_PRINCIPAL, subject, resources) is (
            EvaluationResult.MATCHED
        )

    def test_no_principal_collected_anywhere_is_indeterminate(self) -> None:
        # The coverage guard: an estate-wide zero means the collector
        # did not run far more often than it means the tenant has none.
        subject = role_assignment(principal=None)
        assert self._evaluate(self.NO_PRINCIPAL, subject, [subject]) is (
            EvaluationResult.INDETERMINATE
        )


# ---------------------------------------------------------------------
# Graph invariants
# ---------------------------------------------------------------------


def full_estate(*, collect_principal=True, second_assignment=False):
    resources = [role_assignment(), role_definition(), subscription()]
    if collect_principal:
        resources.append(principal())
    if second_assignment:
        resources.append(
            resource(
                f"{RG_SCOPE}/providers/Microsoft.Authorization/roleAssignments/ra-2",
                "azure_role_assignment",
                {"scope": RG_SCOPE, "is_subscription_scope": False},
                (rel(PRINCIPAL), rel(READER_DEF), rel(RG_SCOPE, RelationshipType.ALLOWS)),
            )
        )
        resources.append(role_definition(READER_DEF, grants_all=False, name="Reader"))
        resources.append(resource(RG_SCOPE, "azure_resource_group", {}))
    return resources


class TestGraphInvariants:
    def test_the_expected_rbac_edges_are_all_present(self) -> None:
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        assert {
            (str(e.source_id), str(e.target_id), e.relationship_type) for e in graph.edges
        } == {
            (ASSIGNMENT, PRINCIPAL, RelationshipType.ATTACHED_TO),
            (ASSIGNMENT, OWNER_DEF, RelationshipType.ATTACHED_TO),
            (ASSIGNMENT, SUBSCRIPTION_SCOPE, RelationshipType.ALLOWS),
        }

    def test_no_dangling_duplicate_or_self_looping_edges(self) -> None:
        report = validate_graph(
            BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        )
        assert report.errors == ()
        for code in ("dangling_edge", "duplicate_edge", "self_loop"):
            assert not [i for i in report.issues if i.code == code]

    def test_no_edge_is_rejected_and_nothing_is_external(self) -> None:
        result = BuildResourceGraph().build_with_report(
            tenant_id=TENANT, resources=full_estate()
        )
        assert result.rejected_edges == ()
        assert result.external_nodes == ()
        assert result.is_complete

    def test_every_edge_endpoint_is_a_node(self) -> None:
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        node_ids = {n.resource_id for n in graph.nodes}
        assert {e.target_id for e in graph.edges} <= node_ids
        assert {e.source_id for e in graph.edges} <= node_ids

    def test_tenant_and_subscription_are_consistent(self) -> None:
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        assert {n.tenant_id for n in graph.nodes} == {TENANT}
        assert {n.account_id for n in graph.nodes} == {SUB}
        report = validate_graph(graph)
        assert not [i for i in report.issues if i.code == "cross_account_edge"]

    def test_no_inverse_edges_are_emitted(self) -> None:
        # One fact, one edge. A principal asserting its own assignments
        # would let the two directions disagree after a partial scan.
        graph = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        assert not [e for e in graph.edges if str(e.source_id) != ASSIGNMENT]


class TestGraphDeterminism:
    def test_the_fingerprint_is_stable_across_identical_input(self) -> None:
        a = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        b = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        assert graph_fingerprint(a) == graph_fingerprint(b)

    def test_the_fingerprint_ignores_collector_ordering(self) -> None:
        forward = full_estate(second_assignment=True)
        a = BuildResourceGraph().build(tenant_id=TENANT, resources=forward)
        b = BuildResourceGraph().build(tenant_id=TENANT, resources=list(reversed(forward)))
        assert graph_fingerprint(a) == graph_fingerprint(b)

    def test_the_fingerprint_changes_when_an_assignment_is_added(self) -> None:
        # The counterpart: a fingerprint that ignored RBAC edges
        # entirely would satisfy both tests above.
        a = BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        b = BuildResourceGraph().build(
            tenant_id=TENANT, resources=full_estate(second_assignment=True)
        )
        assert graph_fingerprint(a) != graph_fingerprint(b)

    def test_validation_counts_are_stable(self) -> None:
        first = validate_graph(
            BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        )
        second = validate_graph(
            BuildResourceGraph().build(tenant_id=TENANT, resources=full_estate())
        )
        assert first.relationship_counts == second.relationship_counts
        assert (first.node_count, first.edge_count) == (
            second.node_count,
            second.edge_count,
        )
        assert all(i.severity is not ValidationSeverity.ERROR for i in first.issues)


class TestUncollectedPrincipalGraph:
    def test_the_edge_survives_and_the_uncertainty_is_explicit(self) -> None:
        result = BuildResourceGraph().build_with_report(
            tenant_id=TENANT, resources=full_estate(collect_principal=False)
        )
        assert ResourceId(PRINCIPAL) in result.external_nodes
        assert result.rejected_edges == ()
        node = next(n for n in result.graph.nodes if str(n.resource_id) == PRINCIPAL)
        assert node.is_external
        assert node.confidence == "medium"

    def test_an_incomplete_graph_is_not_an_invalid_one(self) -> None:
        report = validate_graph(
            BuildResourceGraph().build(
                tenant_id=TENANT, resources=full_estate(collect_principal=False)
            )
        )
        assert report.errors == ()
        assert not [i for i in report.issues if i.code == "orphan_external_node"]


# ---------------------------------------------------------------------
# Registration — the defect class that leaves a collector dead
# ---------------------------------------------------------------------


class TestRbacCollectorsAreRegistered:
    def test_the_default_azure_collector_registers_the_rbac_collectors(self) -> None:
        """A collector nobody registers is dead in production while all
        of its own unit tests pass — the defect that left
        `IamRoleCollector` inert on the AWS side. Asserted explicitly
        rather than trusted.
        """

        from infrastructure.cloud.azure.collector import AzureCollector
        from infrastructure.cloud.azure.resource_collectors.authorization import (
            RoleAssignmentCollector,
            RoleDefinitionCollector,
        )

        class Clients:
            subscription_id = SUB
            storage = network = compute = keyvault = monitor = authorization = object()

        registered = {
            type(c) for c in AzureCollector(clients=Clients(), tenant_id=TENANT)._sub_collectors
        }
        assert RoleDefinitionCollector in registered
        assert RoleAssignmentCollector in registered

    def test_the_pre_existing_collectors_are_still_registered(self) -> None:
        # Adding two must not displace the five that were already there.
        from infrastructure.cloud.azure.collector import AzureCollector

        class Clients:
            subscription_id = SUB
            storage = network = compute = keyvault = monitor = authorization = object()

        names = {
            type(c).__name__
            for c in AzureCollector(clients=Clients(), tenant_id=TENANT)._sub_collectors
        }
        assert {
            "StorageAccountCollector",
            "NetworkSecurityGroupCollector",
            "VirtualMachineCollector",
            "KeyVaultCollector",
            "ActivityLogSettingCollector",
        } <= names
