"""Tests for the Phase 3B additive Rule DSL upgrade: new operators,
collection quantifiers, temporal operators, and relationship-aware
(cross-resource) evaluation. ``tests/unit/domain/test_rules.py`` (the
existing 44 tests) is untouched — this file only adds new coverage.
"""

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


def make_resource(resource_id="r-1", resource_type="s3_bucket", attributes=None, tags=None):
    return NormalizedResource(
        resource_id=ResourceId(resource_id),
        resource_type=resource_type,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags=tags or {},
        relationships=(),
        collected_at=NOW,
    )


class TestNewScalarOperators:
    def test_greater_than_or_equal(self) -> None:
        resource = make_resource(attributes={"count": 5})
        assert evaluate_condition({"field": "count", "operator": "greater_than_or_equal", "value": 5}, resource) is MATCHED
        assert evaluate_condition({"field": "count", "operator": "greater_than_or_equal", "value": 6}, resource) is NOT_MATCHED

    def test_less_than_or_equal(self) -> None:
        resource = make_resource(attributes={"count": 5})
        assert evaluate_condition({"field": "count", "operator": "less_than_or_equal", "value": 5}, resource) is MATCHED
        assert evaluate_condition({"field": "count", "operator": "less_than_or_equal", "value": 4}, resource) is NOT_MATCHED

    def test_starts_with(self) -> None:
        resource = make_resource(attributes={"arn": "arn:aws:iam::123:policy/Admin"})
        assert evaluate_condition({"field": "arn", "operator": "starts_with", "value": "arn:aws:iam"}, resource) is MATCHED
        assert evaluate_condition({"field": "arn", "operator": "starts_with", "value": "arn:aws:s3"}, resource) is NOT_MATCHED

    def test_ends_with(self) -> None:
        resource = make_resource(attributes={"name": "prod-logs-bucket"})
        assert evaluate_condition({"field": "name", "operator": "ends_with", "value": "-bucket"}, resource) is MATCHED

    def test_is_true(self) -> None:
        resource = make_resource(attributes={"public": True})
        assert evaluate_condition({"field": "public", "operator": "is_true"}, resource) is MATCHED
        assert evaluate_condition({"field": "public", "operator": "is_false"}, resource) is NOT_MATCHED

    def test_is_false(self) -> None:
        resource = make_resource(attributes={"encrypted": False})
        assert evaluate_condition({"field": "encrypted", "operator": "is_false"}, resource) is MATCHED

    def test_is_null_when_field_present_but_none(self) -> None:
        resource = make_resource(attributes={"kms_key_id": None})
        assert evaluate_condition({"field": "kms_key_id", "operator": "is_null"}, resource) is MATCHED
        assert evaluate_condition({"field": "kms_key_id", "operator": "is_not_null"}, resource) is NOT_MATCHED

    def test_is_null_when_field_absent_is_indeterminate_not_matched(self) -> None:
        # Absence is not the same fact as "collected and null" — see domain/rules/conditions.py.
        resource = make_resource(attributes={})
        assert evaluate_condition({"field": "kms_key_id", "operator": "is_null"}, resource) is INDETERMINATE

    def test_is_not_null_when_present(self) -> None:
        resource = make_resource(attributes={"kms_key_id": "arn:aws:kms:...:key/abc"})
        assert evaluate_condition({"field": "kms_key_id", "operator": "is_not_null"}, resource) is MATCHED

    def test_matches_regex(self) -> None:
        resource = make_resource(attributes={"action": "s3:*"})
        assert evaluate_condition({"field": "action", "operator": "matches_regex", "value": r"^s3:\*$"}, resource) is MATCHED
        assert evaluate_condition({"field": "action", "operator": "matches_regex", "value": r"^ec2:"}, resource) is NOT_MATCHED

    def test_matches_regex_invalid_pattern_raises_invalid_rule_condition(self) -> None:
        resource = make_resource(attributes={"action": "s3:*"})
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition({"field": "action", "operator": "matches_regex", "value": "(unclosed"}, resource)

    def test_contains_any(self) -> None:
        resource = make_resource(attributes={"actions": ["s3:GetObject", "s3:PutObject"]})
        cond = {"field": "actions", "operator": "contains_any", "value": ["s3:PutObject", "s3:DeleteObject"]}
        assert evaluate_condition(cond, resource) is MATCHED

    def test_contains_all(self) -> None:
        resource = make_resource(attributes={"actions": ["s3:GetObject", "s3:PutObject"]})
        cond_all_present = {"field": "actions", "operator": "contains_all", "value": ["s3:GetObject", "s3:PutObject"]}
        cond_missing_one = {"field": "actions", "operator": "contains_all", "value": ["s3:GetObject", "s3:DeleteObject"]}
        assert evaluate_condition(cond_all_present, resource) is MATCHED
        assert evaluate_condition(cond_missing_one, resource) is NOT_MATCHED


class TestNetworkOperators:
    def test_cidr_contains(self) -> None:
        resource = make_resource(attributes={"cidr": "10.0.0.0/16"})
        assert evaluate_condition({"field": "cidr", "operator": "cidr_contains", "value": "10.0.5.5"}, resource) is MATCHED
        assert evaluate_condition({"field": "cidr", "operator": "cidr_contains", "value": "192.168.1.1"}, resource) is NOT_MATCHED

    def test_cidr_contains_subnet(self) -> None:
        resource = make_resource(attributes={"cidr": "10.0.0.0/16"})
        assert evaluate_condition({"field": "cidr", "operator": "cidr_contains", "value": "10.0.5.0/24"}, resource) is MATCHED

    def test_cidr_is_public(self) -> None:
        resource = make_resource(attributes={"cidr": "0.0.0.0/0"})
        assert evaluate_condition({"field": "cidr", "operator": "cidr_is_public"}, resource) is MATCHED

    def test_cidr_is_public_false_for_private_range(self) -> None:
        resource = make_resource(attributes={"cidr": "10.0.0.0/8"})
        assert evaluate_condition({"field": "cidr", "operator": "cidr_is_public"}, resource) is NOT_MATCHED

    def test_cidr_is_private(self) -> None:
        resource = make_resource(attributes={"cidr": "192.168.0.0/16"})
        assert evaluate_condition({"field": "cidr", "operator": "cidr_is_private"}, resource) is MATCHED

    def test_malformed_cidr_is_indeterminate(self) -> None:
        resource = make_resource(attributes={"cidr": "not-a-cidr"})
        assert evaluate_condition({"field": "cidr", "operator": "cidr_is_public"}, resource) is INDETERMINATE

    def test_port_equals(self) -> None:
        resource = make_resource(attributes={"port": 22})
        assert evaluate_condition({"field": "port", "operator": "port_equals", "value": 22}, resource) is MATCHED

    def test_port_in_range(self) -> None:
        resource = make_resource(attributes={"port": 443})
        assert evaluate_condition({"field": "port", "operator": "port_in_range", "value": [1, 1024]}, resource) is MATCHED
        assert evaluate_condition({"field": "port", "operator": "port_in_range", "value": [2000, 3000]}, resource) is NOT_MATCHED


class TestTemporalOperators:
    def test_age_gt_days_matched(self) -> None:
        resource = make_resource(attributes={"created_at": "2025-01-01T00:00:00+00:00"})
        cond = {"field": "created_at", "operator": "age_gt_days", "value": 90}
        assert evaluate_condition(cond, resource, as_of=NOW) is MATCHED

    def test_age_gt_days_not_matched(self) -> None:
        resource = make_resource(attributes={"created_at": "2025-12-20T00:00:00+00:00"})
        cond = {"field": "created_at", "operator": "age_gt_days", "value": 90}
        assert evaluate_condition(cond, resource, as_of=NOW) is NOT_MATCHED

    def test_age_gte_days_boundary(self) -> None:
        resource = make_resource(attributes={"created_at": "2025-10-03T00:00:00+00:00"})  # exactly 90 days before NOW
        cond = {"field": "created_at", "operator": "age_gte_days", "value": 90}
        assert evaluate_condition(cond, resource, as_of=NOW) is MATCHED

    def test_age_lt_days(self) -> None:
        resource = make_resource(attributes={"created_at": "2025-12-31T00:00:00+00:00"})
        cond = {"field": "created_at", "operator": "age_lt_days", "value": 90}
        assert evaluate_condition(cond, resource, as_of=NOW) is MATCHED

    def test_temporal_operator_without_as_of_raises(self) -> None:
        resource = make_resource(attributes={"created_at": "2025-01-01T00:00:00+00:00"})
        cond = {"field": "created_at", "operator": "age_gt_days", "value": 90}
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(cond, resource)  # no as_of supplied

    def test_temporal_operator_is_deterministic_given_explicit_as_of(self) -> None:
        resource = make_resource(attributes={"created_at": "2025-01-01T00:00:00+00:00"})
        cond = {"field": "created_at", "operator": "age_gt_days", "value": 90}
        results = {evaluate_condition(cond, resource, as_of=NOW) for _ in range(20)}
        assert results == {MATCHED}

    def test_malformed_timestamp_is_indeterminate(self) -> None:
        resource = make_resource(attributes={"created_at": "not-a-date"})
        cond = {"field": "created_at", "operator": "age_gt_days", "value": 90}
        assert evaluate_condition(cond, resource, as_of=NOW) is INDETERMINATE


class TestCollectionQuantifiers:
    def _ingress_resource(self, rules):
        return make_resource(attributes={"ingress_rules": rules})

    def test_any_matched_when_one_element_satisfies(self) -> None:
        resource = self._ingress_resource(
            [{"cidr": "10.0.0.0/8", "port": 443}, {"cidr": "0.0.0.0/0", "port": 22}]
        )
        cond = {
            "field": "ingress_rules",
            "operator": "any",
            "where": {"field": "cidr", "operator": "equals", "value": "0.0.0.0/0"},
        }
        assert evaluate_condition(cond, resource) is MATCHED

    def test_any_not_matched_when_no_element_satisfies(self) -> None:
        resource = self._ingress_resource([{"cidr": "10.0.0.0/8", "port": 443}])
        cond = {
            "field": "ingress_rules",
            "operator": "any",
            "where": {"field": "cidr", "operator": "equals", "value": "0.0.0.0/0"},
        }
        assert evaluate_condition(cond, resource) is NOT_MATCHED

    def test_any_on_empty_collection_is_not_matched(self) -> None:
        resource = self._ingress_resource([])
        cond = {"field": "ingress_rules", "operator": "any", "where": {"field": "cidr", "operator": "exists"}}
        assert evaluate_condition(cond, resource) is NOT_MATCHED

    def test_all_matched_when_every_element_satisfies(self) -> None:
        resource = self._ingress_resource([{"encrypted": True}, {"encrypted": True}])
        cond = {"field": "ingress_rules", "operator": "all", "where": {"field": "encrypted", "operator": "is_true"}}
        assert evaluate_condition(cond, resource) is MATCHED

    def test_all_not_matched_when_one_element_fails(self) -> None:
        resource = self._ingress_resource([{"encrypted": True}, {"encrypted": False}])
        cond = {"field": "ingress_rules", "operator": "all", "where": {"field": "encrypted", "operator": "is_true"}}
        assert evaluate_condition(cond, resource) is NOT_MATCHED

    def test_all_on_empty_collection_is_vacuously_matched(self) -> None:
        resource = self._ingress_resource([])
        cond = {"field": "ingress_rules", "operator": "all", "where": {"field": "encrypted", "operator": "is_true"}}
        assert evaluate_condition(cond, resource) is MATCHED

    def test_none_matched_when_nothing_satisfies(self) -> None:
        resource = self._ingress_resource([{"cidr": "10.0.0.0/8"}])
        cond = {
            "field": "ingress_rules",
            "operator": "none",
            "where": {"field": "cidr", "operator": "equals", "value": "0.0.0.0/0"},
        }
        assert evaluate_condition(cond, resource) is MATCHED

    def test_none_not_matched_when_something_satisfies(self) -> None:
        resource = self._ingress_resource([{"cidr": "0.0.0.0/0"}])
        cond = {
            "field": "ingress_rules",
            "operator": "none",
            "where": {"field": "cidr", "operator": "equals", "value": "0.0.0.0/0"},
        }
        assert evaluate_condition(cond, resource) is NOT_MATCHED

    def test_quantifier_on_missing_field_is_indeterminate(self) -> None:
        resource = make_resource(attributes={})
        cond = {"field": "ingress_rules", "operator": "any", "where": {"field": "cidr", "operator": "exists"}}
        assert evaluate_condition(cond, resource) is INDETERMINATE

    def test_quantifier_on_non_collection_field_is_indeterminate(self) -> None:
        resource = make_resource(attributes={"ingress_rules": "not-a-list"})
        cond = {"field": "ingress_rules", "operator": "any", "where": {"field": "cidr", "operator": "exists"}}
        assert evaluate_condition(cond, resource) is INDETERMINATE

    def test_quantifier_where_supports_nested_and_or(self) -> None:
        resource = self._ingress_resource([{"cidr": "0.0.0.0/0", "port": 22}])
        cond = {
            "field": "ingress_rules",
            "operator": "any",
            "where": {
                "and": [
                    {"field": "cidr", "operator": "equals", "value": "0.0.0.0/0"},
                    {"field": "port", "operator": "equals", "value": 22},
                ]
            },
        }
        assert evaluate_condition(cond, resource) is MATCHED

    def test_relationship_condition_inside_where_is_rejected(self) -> None:
        resource = self._ingress_resource([{"cidr": "0.0.0.0/0"}])
        cond = {
            "field": "ingress_rules",
            "operator": "any",
            "where": {"relationship": "attached_to", "direction": "outgoing", "where": {"field": "x", "operator": "exists"}},
        }
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(cond, resource)


class TestRelationshipConditions:
    def _graph_and_resources(self):
        graph = ResourceGraph(tenant_id=TENANT)
        graph.add_node(GraphNode(resource_id=ResourceId("ec2-1"), tenant_id=TENANT, resource_type="ec2_instance"))
        graph.add_node(GraphNode(resource_id=ResourceId("sg-open"), tenant_id=TENANT, resource_type="security_group"))
        graph.add_edge(
            GraphEdge(source_id=ResourceId("ec2-1"), target_id=ResourceId("sg-open"), relationship_type=RelationshipType.ATTACHED_TO)
        )
        ec2 = make_resource("ec2-1", resource_type="ec2_instance", attributes={"public_ip": "1.2.3.4"})
        sg = make_resource("sg-open", resource_type="security_group", attributes={"unrestricted_ingress_ports": (22,)})
        resources_by_id = {ec2.resource_id: ec2, sg.resource_id: sg}
        return graph, ec2, resources_by_id

    def test_relationship_matched_when_neighbor_satisfies_where(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {
            "relationship": "attached_to",
            "direction": "outgoing",
            "where": {"field": "unrestricted_ingress_ports", "operator": "contains", "value": 22},
        }
        result = evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)
        assert result is MATCHED

    def test_relationship_not_matched_when_no_neighbor_satisfies(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {
            "relationship": "attached_to",
            "direction": "outgoing",
            "where": {"field": "unrestricted_ingress_ports", "operator": "contains", "value": 3389},
        }
        result = evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)
        assert result is NOT_MATCHED

    def test_relationship_not_matched_when_no_such_edge_exists(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {"relationship": "allows", "direction": "outgoing", "where": {"field": "x", "operator": "exists"}}
        result = evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)
        assert result is NOT_MATCHED

    def test_relationship_target_type_filter(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {
            "relationship": "attached_to",
            "direction": "outgoing",
            "target_type": "kms_key",  # neighbor is a security_group, not a kms_key
            "where": {"field": "unrestricted_ingress_ports", "operator": "contains", "value": 22},
        }
        result = evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)
        assert result is NOT_MATCHED

    def test_relationship_without_graph_raises_invalid_rule_condition(self) -> None:
        _, ec2, resources_by_id = self._graph_and_resources()
        cond = {"relationship": "attached_to", "direction": "outgoing", "where": {"field": "x", "operator": "exists"}}
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(cond, ec2, resources_by_id=resources_by_id)  # graph omitted

    def test_relationship_with_unknown_type_raises(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {"relationship": "not_a_real_relationship", "direction": "outgoing", "where": {"field": "x", "operator": "exists"}}
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)

    def test_relationship_with_invalid_direction_raises(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {"relationship": "attached_to", "direction": "sideways", "where": {"field": "x", "operator": "exists"}}
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)

    def test_neighbor_missing_from_resources_by_id_is_indeterminate(self) -> None:
        graph, ec2, _ = self._graph_and_resources()
        cond = {"relationship": "attached_to", "direction": "outgoing", "where": {"field": "x", "operator": "exists"}}
        result = evaluate_condition(cond, ec2, graph=graph, resources_by_id={})
        assert result is INDETERMINATE

    def test_relationship_can_compose_with_and(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {
            "and": [
                {"field": "public_ip", "operator": "exists"},
                {
                    "relationship": "attached_to",
                    "direction": "outgoing",
                    "where": {"field": "unrestricted_ingress_ports", "operator": "contains", "value": 22},
                },
            ]
        }
        result = evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id)
        assert result is MATCHED

    def test_relationship_evaluation_is_deterministic(self) -> None:
        graph, ec2, resources_by_id = self._graph_and_resources()
        cond = {
            "relationship": "attached_to",
            "direction": "outgoing",
            "where": {"field": "unrestricted_ingress_ports", "operator": "contains", "value": 22},
        }
        results = {evaluate_condition(cond, ec2, graph=graph, resources_by_id=resources_by_id) for _ in range(20)}
        assert results == {MATCHED}


class TestBackwardCompatibility:
    def test_existing_leaf_shape_still_works_unchanged(self) -> None:
        resource = make_resource(attributes={"encrypted": False})
        cond = {"field": "encrypted", "operator": "equals", "value": True}
        assert evaluate_condition(cond, resource) is NOT_MATCHED

    def test_existing_and_or_not_still_work_unchanged(self) -> None:
        resource = make_resource(attributes={"a": True, "b": False})
        cond = {"and": [{"field": "a", "operator": "equals", "value": True}, {"not": {"field": "b", "operator": "equals", "value": True}}]}
        assert evaluate_condition(cond, resource) is MATCHED

    def test_new_optional_params_default_to_none_safely(self) -> None:
        resource = make_resource(attributes={"a": True})
        # No graph, no resources_by_id, no as_of — must behave exactly as before.
        assert evaluate_condition({"field": "a", "operator": "equals", "value": True}, resource) is MATCHED
