from datetime import datetime, timezone

import pytest

from domain.resources.models import NormalizedResource
from domain.rules.conditions import EvaluationResult, evaluate_condition
from domain.rules.rule import Rule
from domain.shared.enums import CloudProvider, Severity
from domain.shared.errors import InvalidRuleCondition
from domain.shared.identifiers import ResourceId, RuleId, TenantId

MATCHED = EvaluationResult.MATCHED
NOT_MATCHED = EvaluationResult.NOT_MATCHED
INDETERMINATE = EvaluationResult.INDETERMINATE


def make_resource(attributes=None, tags=None) -> NormalizedResource:
    return NormalizedResource(
        resource_id=ResourceId("s3-bucket-1"),
        resource_type="s3_bucket",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="us-east-1",
        attributes=attributes or {},
        tags=tags or {},
        relationships=(),
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def make_rule(condition) -> Rule:
    return Rule(
        id=RuleId("rule-1"),
        framework="CIS",
        control_id="CIS-1.1",
        domain="storage",
        severity=Severity.HIGH,
        condition=condition,
    )


class TestRule:
    def test_valid_rule(self) -> None:
        rule = make_rule({"field": "encrypted", "operator": "equals", "value": True})
        assert rule.id == RuleId("rule-1")
        assert rule.severity is Severity.HIGH

    @pytest.mark.parametrize("bad_field", ["framework", "control_id", "domain"])
    def test_blank_metadata_field_is_rejected(self, bad_field) -> None:
        kwargs = dict(
            id=RuleId("rule-1"),
            framework="CIS",
            control_id="CIS-1.1",
            domain="storage",
            severity=Severity.HIGH,
            condition={"field": "x", "operator": "exists"},
        )
        kwargs[bad_field] = "   "
        with pytest.raises(Exception):
            Rule(**kwargs)

    def test_empty_condition_is_rejected_at_construction(self) -> None:
        with pytest.raises(InvalidRuleCondition):
            make_rule({})


class TestOperators:
    @pytest.mark.parametrize(
        "operator,attr_value,rule_value,expected",
        [
            ("equals", True, True, MATCHED),
            ("equals", False, True, NOT_MATCHED),
            ("not_equals", False, True, MATCHED),
            ("not_equals", True, True, NOT_MATCHED),
            ("greater_than", 10, 5, MATCHED),
            ("greater_than", 3, 5, NOT_MATCHED),
            ("less_than", 3, 5, MATCHED),
            ("less_than", 10, 5, NOT_MATCHED),
            ("contains", ["a", "b"], "a", MATCHED),
            ("contains", ["a", "b"], "z", NOT_MATCHED),
            ("not_contains", ["a", "b"], "z", MATCHED),
            ("not_contains", ["a", "b"], "a", NOT_MATCHED),
            ("in", "prod", ["prod", "staging"], MATCHED),
            ("in", "dev", ["prod", "staging"], NOT_MATCHED),
            ("not_in", "dev", ["prod", "staging"], MATCHED),
            ("not_in", "prod", ["prod", "staging"], NOT_MATCHED),
        ],
    )
    def test_operator_semantics(self, operator, attr_value, rule_value, expected) -> None:
        resource = make_resource(attributes={"attr": attr_value})
        condition = {"field": "attr", "operator": operator, "value": rule_value}
        assert evaluate_condition(condition, resource) is expected

    def test_exists_true_when_field_present(self) -> None:
        resource = make_resource(attributes={"encrypted": False})
        condition = {"field": "encrypted", "operator": "exists"}
        assert evaluate_condition(condition, resource) is MATCHED

    def test_exists_false_when_field_absent(self) -> None:
        resource = make_resource(attributes={})
        condition = {"field": "encrypted", "operator": "exists"}
        assert evaluate_condition(condition, resource) is NOT_MATCHED

    def test_not_exists_is_inverse_of_exists(self) -> None:
        resource = make_resource(attributes={})
        condition = {"field": "encrypted", "operator": "not_exists"}
        assert evaluate_condition(condition, resource) is MATCHED

    def test_nested_field_path_is_resolved_with_dot_notation(self) -> None:
        resource = make_resource(attributes={"versioning": {"enabled": True}})
        condition = {"field": "versioning.enabled", "operator": "equals", "value": True}
        assert evaluate_condition(condition, resource) is MATCHED

    def test_tags_source_is_evaluated_against_tags_not_attributes(self) -> None:
        resource = make_resource(attributes={}, tags={"env": "prod"})
        condition = {"source": "tags", "field": "env", "operator": "equals", "value": "prod"}
        assert evaluate_condition(condition, resource) is MATCHED

    def test_unknown_operator_raises_invalid_rule_condition(self) -> None:
        resource = make_resource(attributes={"x": 1})
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition({"field": "x", "operator": "roughly_equals", "value": 1}, resource)

    def test_incomparable_types_yield_indeterminate_not_a_crash(self) -> None:
        resource = make_resource(attributes={"x": "not-a-number"})
        condition = {"field": "x", "operator": "greater_than", "value": 5}
        assert evaluate_condition(condition, resource) is INDETERMINATE


class TestMissingAttributeBehavior:
    def test_missing_field_is_indeterminate_for_comparison_operators(self) -> None:
        resource = make_resource(attributes={})
        condition = {"field": "encrypted", "operator": "equals", "value": True}
        assert evaluate_condition(condition, resource) is INDETERMINATE

    def test_missing_field_never_silently_passes_as_matched_or_not_matched(self) -> None:
        resource = make_resource(attributes={})
        for operator, value in [
            ("equals", True),
            ("not_equals", True),
            ("greater_than", 1),
            ("less_than", 1),
            ("contains", "a"),
            ("in", ["a"]),
        ]:
            condition = {"field": "missing", "operator": operator, "value": value}
            assert evaluate_condition(condition, resource) is INDETERMINATE


class TestLogicalCombinators:
    def _leaf(self, value: bool) -> dict:
        return {"field": "flag", "operator": "equals", "value": value}

    def test_and_matched_only_when_all_matched(self) -> None:
        resource = make_resource(attributes={"flag": True})
        condition = {"and": [self._leaf(True), self._leaf(True)]}
        assert evaluate_condition(condition, resource) is MATCHED

    def test_and_is_not_matched_if_any_branch_not_matched_even_with_indeterminate(self) -> None:
        resource = make_resource(attributes={"flag": True})
        condition = {
            "and": [
                self._leaf(False),  # NOT_MATCHED
                {"field": "missing", "operator": "equals", "value": 1},  # INDETERMINATE
            ]
        }
        assert evaluate_condition(condition, resource) is NOT_MATCHED

    def test_and_is_indeterminate_when_no_not_matched_but_one_indeterminate(self) -> None:
        resource = make_resource(attributes={"flag": True})
        condition = {
            "and": [
                self._leaf(True),  # MATCHED
                {"field": "missing", "operator": "equals", "value": 1},  # INDETERMINATE
            ]
        }
        assert evaluate_condition(condition, resource) is INDETERMINATE

    def test_or_matched_if_any_branch_matched_even_with_indeterminate(self) -> None:
        resource = make_resource(attributes={"flag": True})
        condition = {
            "or": [
                self._leaf(True),
                {"field": "missing", "operator": "equals", "value": 1},
            ]
        }
        assert evaluate_condition(condition, resource) is MATCHED

    def test_or_not_matched_only_when_all_not_matched(self) -> None:
        resource = make_resource(attributes={"flag": True})
        condition = {"or": [self._leaf(False), self._leaf(False)]}
        assert evaluate_condition(condition, resource) is NOT_MATCHED

    def test_or_is_indeterminate_when_no_matched_but_one_indeterminate(self) -> None:
        resource = make_resource(attributes={"flag": True})
        condition = {
            "or": [
                self._leaf(False),
                {"field": "missing", "operator": "equals", "value": 1},
            ]
        }
        assert evaluate_condition(condition, resource) is INDETERMINATE

    def test_not_inverts_matched_and_not_matched(self) -> None:
        resource = make_resource(attributes={"flag": True})
        assert evaluate_condition({"not": self._leaf(True)}, resource) is NOT_MATCHED
        assert evaluate_condition({"not": self._leaf(False)}, resource) is MATCHED

    def test_not_of_indeterminate_stays_indeterminate(self) -> None:
        resource = make_resource(attributes={})
        condition = {"not": {"field": "missing", "operator": "equals", "value": 1}}
        assert evaluate_condition(condition, resource) is INDETERMINATE

    def test_and_or_not_can_be_arbitrarily_nested(self) -> None:
        resource = make_resource(attributes={"a": True, "b": False, "c": True})
        condition = {
            "and": [
                {"or": [self._field_eq("a", True), self._field_eq("b", True)]},
                {"not": self._field_eq("c", False)},
            ]
        }
        assert evaluate_condition(condition, resource) is MATCHED

    def _field_eq(self, field: str, value) -> dict:
        return {"field": field, "operator": "equals", "value": value}

    def test_and_with_no_operands_is_rejected(self) -> None:
        resource = make_resource(attributes={})
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition({"and": []}, resource)

    def test_malformed_condition_shape_is_rejected(self) -> None:
        resource = make_resource(attributes={})
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition({"nonsense": True}, resource)


class TestGraphSourceLeaf:
    def test_graph_leaf_with_unregistered_function_is_rejected(self) -> None:
        resource = make_resource(attributes={})
        condition = {"source": "graph", "function": "is_publicly_reachable"}
        with pytest.raises(InvalidRuleCondition):
            evaluate_condition(condition, resource)


class TestDeterminism:
    def test_same_rule_same_resource_always_yields_same_result(self) -> None:
        resource = make_resource(attributes={"encrypted": False})
        rule = make_rule({"field": "encrypted", "operator": "equals", "value": True})
        results = {rule.evaluate(resource) for _ in range(50)}
        assert results == {NOT_MATCHED}

    def test_no_eval_or_exec_used_anywhere_in_the_module(self) -> None:
        import inspect

        import domain.rules.conditions as conditions_module

        source = inspect.getsource(conditions_module)
        assert "eval(" not in source
        assert "exec(" not in source
