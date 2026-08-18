"""Tests for the absence-quantified ``no_relationship`` condition.

The control class this unlocks — *critical database with no private
endpoint*, *resource with no diagnostic settings* — is also the most
dangerous one to get wrong, because its failure mode is inverted from
everything else in this codebase. Elsewhere an unknown silently becoming
``False`` hides a violation. Here an unknown silently becoming ``True``
**invents** one, across the entire estate at once.

So most of this file is about the coverage guard, not about counting
edges.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from domain.graph.models import GraphEdge, GraphNode, ResourceGraph
from domain.resources.models import NormalizedResource
from domain.rules.conditions import EvaluationResult, evaluate_condition
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.errors import InvalidRuleCondition
from domain.shared.identifiers import ResourceId, TenantId

MATCHED = EvaluationResult.MATCHED
NOT_MATCHED = EvaluationResult.NOT_MATCHED
INDETERMINATE = EvaluationResult.INDETERMINATE

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_resource(resource_id, resource_type, attributes=None) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AZURE,
        tenant_id=TENANT,
        region="westeurope",
        attributes=attributes or {},
        tags={},
        relationships=(),
        collected_at=NOW,
    )


def scenario(*, endpoint_connected: bool, endpoint_collected: bool = True):
    """A database, and optionally a private endpoint connected to it.

    ``endpoint_collected=False`` models the dangerous case: the private
    endpoint collector never ran, so the graph contains no endpoint node
    at all and the database *looks* unprotected.
    """

    graph = ResourceGraph(tenant_id=TENANT)
    db = make_resource("db-1", "azure_sql")
    graph.add_node(
        GraphNode(resource_id=db.resource_id, tenant_id=TENANT, resource_type="azure_sql")
    )
    resources = {db.resource_id: db}

    if endpoint_collected:
        pe = make_resource("pe-1", "private_endpoint", attributes={"approved": True})
        graph.add_node(
            GraphNode(
                resource_id=pe.resource_id, tenant_id=TENANT, resource_type="private_endpoint"
            )
        )
        resources[pe.resource_id] = pe
        if endpoint_connected:
            graph.add_edge(
                GraphEdge(
                    source_id=db.resource_id,
                    target_id=pe.resource_id,
                    relationship_type=RelationshipType.CONNECTS_TO,
                )
            )

    return graph, db, resources


NO_PRIVATE_ENDPOINT = {
    "no_relationship": "connects_to",
    "direction": "outgoing",
    "target_type": "private_endpoint",
}


class TestAbsenceTruthTable:
    def test_matched_when_the_relationship_is_genuinely_absent(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is MATCHED

    def test_not_matched_when_the_relationship_exists(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is NOT_MATCHED

    def test_a_different_relationship_type_does_not_satisfy_the_requirement(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        pe = ResourceId("pe-1")
        graph.add_edge(
            GraphEdge(
                source_id=db.resource_id,
                target_id=pe,
                relationship_type=RelationshipType.ATTACHED_TO,
            )
        )
        # ATTACHED_TO is not CONNECTS_TO. "Has some relationship" must
        # never be read as "has the required relationship".
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is MATCHED

    def test_a_wrongly_typed_neighbour_does_not_satisfy_the_requirement(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        graph.add_node(
            GraphNode(
                resource_id=ResourceId("vnet-1"), tenant_id=TENANT, resource_type="azure_vnet"
            )
        )
        graph.add_edge(
            GraphEdge(
                source_id=db.resource_id,
                target_id=ResourceId("vnet-1"),
                relationship_type=RelationshipType.CONNECTS_TO,
            )
        )
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is MATCHED

    def test_direction_is_respected(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        graph.add_edge(
            GraphEdge(
                source_id=ResourceId("pe-1"),
                target_id=db.resource_id,
                relationship_type=RelationshipType.CONNECTS_TO,
            )
        )
        # The endpoint points at the database. Outgoing is still absent...
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is MATCHED
        # ...incoming is not.
        assert evaluate_condition(
            {**NO_PRIVATE_ENDPOINT, "direction": "incoming"},
            db,
            graph=graph,
            resources_by_id=resources,
        ) is NOT_MATCHED


class TestCoverageGuard:
    """The reason this node exists in the shape it does."""

    def test_a_collector_that_never_ran_yields_indeterminate_not_a_finding(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False, endpoint_collected=False)
        # Structurally identical to a genuinely unprotected database. If
        # this returned MATCHED, a missing permission would report the
        # entire estate as non-compliant.
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is INDETERMINATE

    def test_the_same_graph_shape_differs_only_by_collector_coverage(self) -> None:
        uncovered, db_a, res_a = scenario(endpoint_connected=False, endpoint_collected=False)
        covered, db_b, res_b = scenario(endpoint_connected=False, endpoint_collected=True)

        # Neither database has the edge. The ONLY difference is whether
        # anything of the required type was collected at all — and that
        # is what separates a data gap from a finding.
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db_a, graph=uncovered, resources_by_id=res_a
        ) is INDETERMINATE
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db_b, graph=covered, resources_by_id=res_b
        ) is MATCHED

    def test_requires_collected_can_be_stated_explicitly(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {
            "no_relationship": "connects_to",
            "direction": "outgoing",
            "requires_collected": "diagnostic_setting",
        }
        # Nothing of type diagnostic_setting was collected, so absence
        # cannot be asserted even though the edge is genuinely missing.
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is INDETERMINATE

    def test_explicit_requires_collected_overrides_the_target_type_default(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {**NO_PRIVATE_ENDPOINT, "requires_collected": "azure_sql"}
        # azure_sql WAS collected, so the guard passes even though
        # target_type (private_endpoint) is what gets filtered on.
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is MATCHED

    def test_a_condition_with_no_coverage_signal_is_rejected(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {"no_relationship": "connects_to", "direction": "outgoing"}
        # No target_type to default from and no explicit guard. Guessing
        # one would defeat the whole mechanism, so this is a rule-
        # authoring error, surfaced loudly.
        with pytest.raises(InvalidRuleCondition, match="requires_collected"):
            evaluate_condition(cond, db, graph=graph, resources_by_id=resources)

    def test_a_blank_requires_collected_is_rejected(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {**NO_PRIVATE_ENDPOINT, "requires_collected": "   "}
        with pytest.raises(InvalidRuleCondition, match="requires_collected"):
            evaluate_condition(cond, db, graph=graph, resources_by_id=resources)

    def test_the_guard_is_checked_before_edges_are_counted(self) -> None:
        """Ordering matters, not just the outcome.

        Even when the resource DOES have the edge, an unsatisfied guard
        means the graph is not trustworthy for this question — reporting
        a confident NOT_MATCHED off an uncollected type would be the same
        mistake in the compliant direction.
        """

        graph, db, resources = scenario(endpoint_connected=True)
        cond = {**NO_PRIVATE_ENDPOINT, "requires_collected": "never_collected_type"}
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is INDETERMINATE


class TestAbsenceWithWhereClause:
    """``where`` narrows what counts as satisfying the requirement.

    "No *approved* private endpoint" is a stricter control than "no
    private endpoint", and an unapproved one must not silently satisfy it.
    """

    def test_matched_when_no_neighbour_satisfies_where(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        unapproved = make_resource("pe-1", "private_endpoint", attributes={"approved": False})
        resources[unapproved.resource_id] = unapproved
        cond = {**NO_PRIVATE_ENDPOINT, "where": {"field": "approved", "operator": "is_true"}}
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is MATCHED

    def test_not_matched_when_a_neighbour_satisfies_where(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        cond = {**NO_PRIVATE_ENDPOINT, "where": {"field": "approved", "operator": "is_true"}}
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is NOT_MATCHED

    def test_an_unreadable_neighbour_yields_indeterminate_not_matched(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        del resources[ResourceId("pe-1")]  # in the graph, not in the resource set
        cond = {**NO_PRIVATE_ENDPOINT, "where": {"field": "approved", "operator": "is_true"}}
        # "We cannot tell whether an approved endpoint exists" is not
        # "no approved endpoint exists".
        assert evaluate_condition(
            cond, db, graph=graph, resources_by_id=resources
        ) is INDETERMINATE

    def test_an_unknown_attribute_on_a_neighbour_propagates_indeterminate(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        resources[ResourceId("pe-1")] = make_resource("pe-1", "private_endpoint", attributes={})
        cond = {**NO_PRIVATE_ENDPOINT, "where": {"field": "approved", "operator": "is_true"}}
        assert evaluate_condition(
            cond, db, graph=graph, resources_by_id=resources
        ) is INDETERMINATE

    def test_a_satisfying_neighbour_wins_over_an_unreadable_one(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        graph.add_node(
            GraphNode(
                resource_id=ResourceId("pe-2"), tenant_id=TENANT, resource_type="private_endpoint"
            )
        )
        graph.add_edge(
            GraphEdge(
                source_id=db.resource_id,
                target_id=ResourceId("pe-2"),
                relationship_type=RelationshipType.CONNECTS_TO,
            )
        )
        # pe-2 is unreadable, but pe-1 is approved — the requirement is
        # definitively met, so the unknown cannot make it indeterminate.
        cond = {**NO_PRIVATE_ENDPOINT, "where": {"field": "approved", "operator": "is_true"}}
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is NOT_MATCHED

    def test_an_unreadable_neighbour_without_where_is_still_determinate(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        del resources[ResourceId("pe-1")]
        # No `where`: the question is purely structural. The edge exists,
        # so the absence is falsified whether or not we can read the
        # neighbour's attributes.
        assert evaluate_condition(
            NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources
        ) is NOT_MATCHED

    def test_a_non_mapping_where_is_rejected(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        cond = {**NO_PRIVATE_ENDPOINT, "where": "approved"}
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(cond, db, graph=graph, resources_by_id=resources)


class TestStructuralValidation:
    def test_missing_graph_is_a_wiring_bug_not_a_data_gap(self) -> None:
        db = make_resource("db-1", "azure_sql")
        with pytest.raises(InvalidRuleCondition, match="caller wiring"):
            evaluate_condition(NO_PRIVATE_ENDPOINT, db)

    def test_missing_resources_by_id_is_a_wiring_bug(self) -> None:
        graph, db, _ = scenario(endpoint_connected=False)
        with pytest.raises(InvalidRuleCondition, match="caller wiring"):
            evaluate_condition(NO_PRIVATE_ENDPOINT, db, graph=graph)

    def test_unknown_relationship_type_is_rejected(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {**NO_PRIVATE_ENDPOINT, "no_relationship": "teleports_to"}
        with pytest.raises(InvalidRuleCondition, match="unknown relationship type"):
            evaluate_condition(cond, db, graph=graph, resources_by_id=resources)

    def test_invalid_direction_is_rejected(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {**NO_PRIVATE_ENDPOINT, "direction": "sideways"}
        with pytest.raises(InvalidRuleCondition, match="direction"):
            evaluate_condition(cond, db, graph=graph, resources_by_id=resources)

    def test_rejected_inside_a_quantifier_where_clause(self) -> None:
        # Same reason `relationship` is rejected there: a bare collection
        # element has no resource identity to traverse from.
        resource = make_resource("db-1", "azure_sql", attributes={"rules": [{"port": 22}]})
        cond = {
            "field": "rules",
            "operator": "any",
            "where": NO_PRIVATE_ENDPOINT,
        }
        graph, _, resources = scenario(endpoint_connected=False)
        with pytest.raises(InvalidRuleCondition, match="no_relationship"):
            evaluate_condition(cond, resource, graph=graph, resources_by_id=resources)


class TestCompositionAndDeterminism:
    def test_composes_with_and_over_a_resource_attribute(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        resources[db.resource_id] = make_resource(
            "db-1", "azure_sql", attributes={"public_network_access": True}
        )
        cond = {
            "and": [
                {"field": "public_network_access", "operator": "is_true"},
                NO_PRIVATE_ENDPOINT,
            ]
        }
        assert evaluate_condition(
            cond, resources[db.resource_id], graph=graph, resources_by_id=resources
        ) is MATCHED

    def test_indeterminate_absence_poisons_the_conjunction(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False, endpoint_collected=False)
        resources[db.resource_id] = make_resource(
            "db-1", "azure_sql", attributes={"public_network_access": True}
        )
        cond = {
            "and": [
                {"field": "public_network_access", "operator": "is_true"},
                NO_PRIVATE_ENDPOINT,
            ]
        }
        # A true attribute must not carry an uncollected absence to a
        # finding — this is the Kleene AND doing its job.
        assert evaluate_condition(
            cond, resources[db.resource_id], graph=graph, resources_by_id=resources
        ) is INDETERMINATE

    def test_evaluation_is_deterministic(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        results = {
            evaluate_condition(NO_PRIVATE_ENDPOINT, db, graph=graph, resources_by_id=resources)
            for _ in range(20)
        }
        assert results == {MATCHED}


class TestExistingRelationshipNodeIsUnchanged:
    """The audit's named regression risk: seven shipped rules rely on the
    existence-quantified truth table. Absence was added as a separate
    node precisely so none of them could shift.
    """

    def test_relationship_still_matches_on_an_existing_edge(self) -> None:
        graph, db, resources = scenario(endpoint_connected=True)
        cond = {
            "relationship": "connects_to",
            "direction": "outgoing",
            "target_type": "private_endpoint",
            "where": {"field": "approved", "operator": "is_true"},
        }
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is MATCHED

    def test_relationship_with_no_neighbours_is_still_vacuously_not_matched(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False)
        cond = {
            "relationship": "connects_to",
            "direction": "outgoing",
            "where": {"field": "approved", "operator": "is_true"},
        }
        # NOT_MATCHED, not INDETERMINATE and not MATCHED — the existing
        # semantics, untouched. `no_relationship` is where absence lives.
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is NOT_MATCHED

    def test_relationship_has_no_coverage_guard_by_design(self) -> None:
        graph, db, resources = scenario(endpoint_connected=False, endpoint_collected=False)
        cond = {
            "relationship": "connects_to",
            "direction": "outgoing",
            "target_type": "private_endpoint",
            "where": {"field": "approved", "operator": "is_true"},
        }
        # An existence question does not need one: "no edge observed"
        # correctly means "no evidence of exposure", which is the safe
        # direction. Only absence questions invert that.
        assert evaluate_condition(cond, db, graph=graph, resources_by_id=resources) is NOT_MATCHED
