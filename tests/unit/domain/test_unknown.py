"""Tests for the UNKNOWN tri-state (audit G3, brief §34).

The requirement in one sentence: **never convert unknown into false**.

These tests exist because the failure mode is silent. A collector that
emits `False` for an undeterminable value produces a finding that looks
exactly like a true positive — "this administrator has no MFA" — when the
real fact is "we lack permission to read MFA state". That is a false
accusation, and it discredits every other finding in the report.
"""

from __future__ import annotations

import copy
import pickle

import pytest

from domain.rules.conditions import EvaluationResult, evaluate_condition
from domain.shared.enums import CloudProvider
from domain.shared.identifiers import ResourceId, TenantId
from domain.shared.unknown import (
    UNKNOWN,
    UnknownType,
    is_known,
    is_unknown,
    to_wire,
    tri_state,
    unknown_if_none,
)


def a_resource(**attributes):
    from datetime import datetime, timezone

    from domain.resources.models import NormalizedResource

    return NormalizedResource(
        resource_id=ResourceId("user-1"),
        resource_type="iam_user",
        cloud_provider=CloudProvider.AWS,
        tenant_id=TenantId("acme"),
        region="us-east-1",
        attributes=attributes,
        tags={},
        relationships=(),
        collected_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


class TestSingleton:
    def test_it_is_a_singleton(self) -> None:
        assert UnknownType() is UNKNOWN

    def test_copies_preserve_identity(self) -> None:
        # Identity is the equality mechanism, so a copy that broke it
        # would silently turn UNKNOWN into a non-UNKNOWN object.
        assert copy.copy(UNKNOWN) is UNKNOWN
        assert copy.deepcopy(UNKNOWN) is UNKNOWN

    def test_it_survives_pickling(self) -> None:
        assert pickle.loads(pickle.dumps(UNKNOWN)) is UNKNOWN

    def test_it_is_hashable(self) -> None:
        assert {UNKNOWN: "ok"}[UNKNOWN] == "ok"

    def test_equality_is_identity_based(self) -> None:
        assert UNKNOWN == UNKNOWN
        assert UNKNOWN != False  # noqa: E712 - the whole point
        assert UNKNOWN != None  # noqa: E711
        assert UNKNOWN != 0
        assert UNKNOWN != "unknown"


class TestTruthinessRefusal:
    def test_bool_raises_rather_than_returning_false(self) -> None:
        # THE safety mechanism. `if value:` on an unknown is the most
        # likely misuse and would silently report a violation.
        with pytest.raises(TypeError, match="no truth value"):
            bool(UNKNOWN)

    def test_using_it_in_an_if_raises(self) -> None:
        with pytest.raises(TypeError):
            if UNKNOWN:  # noqa: SIM103
                pass

    def test_the_error_message_says_what_to_do_instead(self) -> None:
        with pytest.raises(TypeError) as caught:
            bool(UNKNOWN)
        assert "is_unknown" in str(caught.value)

    def test_explicit_identity_comparison_still_works(self) -> None:
        # The safe alternatives must remain ergonomic.
        assert (UNKNOWN is True) is False
        assert (UNKNOWN is False) is False
        assert is_unknown(UNKNOWN)
        assert not is_known(UNKNOWN)


class TestHelpers:
    def test_tri_state_returns_the_value_when_determined(self) -> None:
        assert tri_state(determined=True, value=False) is False
        assert tri_state(determined=True, value=True) is True

    def test_tri_state_returns_unknown_when_undetermined(self) -> None:
        # The collector call-site idiom: a denied API call must not
        # become `False`.
        assert tri_state(determined=False, value=False) is UNKNOWN

    def test_unknown_if_none_maps_only_none(self) -> None:
        assert unknown_if_none(None) is UNKNOWN
        assert unknown_if_none(False) is False
        assert unknown_if_none(0) == 0

    def test_to_wire_renders_a_string(self) -> None:
        assert to_wire(UNKNOWN) == "unknown"

    def test_to_wire_recurses(self) -> None:
        payload = {"mfa": UNKNOWN, "nested": {"x": UNKNOWN}, "items": [UNKNOWN, True]}
        assert to_wire(payload) == {
            "mfa": "unknown",
            "nested": {"x": "unknown"},
            "items": ["unknown", True],
        }

    def test_to_wire_leaves_known_values_alone(self) -> None:
        assert to_wire({"a": 1, "b": False, "c": None}) == {"a": 1, "b": False, "c": None}


class TestRuleEngineIntegration:
    """The part that actually prevents false positives."""

    @pytest.mark.parametrize(
        "operator,value",
        [
            ("equals", False),
            ("not_equals", True),
            ("is_false", None),
            ("is_true", None),
            ("greater_than", 0),
            ("contains", "x"),
            ("in", [1, 2]),
        ],
    )
    def test_every_comparison_against_unknown_is_indeterminate(self, operator, value) -> None:
        condition = {"field": "mfa_enabled", "operator": operator}
        if value is not None:
            condition["value"] = value
        result = evaluate_condition(condition, a_resource(mfa_enabled=UNKNOWN))
        assert result is EvaluationResult.INDETERMINATE

    def test_unknown_does_not_become_a_violation(self) -> None:
        # The false-positive case: a rule looking for `mfa_enabled == false`
        # must NOT fire when the value could not be determined.
        result = evaluate_condition(
            {"field": "mfa_enabled", "operator": "is_false"},
            a_resource(mfa_enabled=UNKNOWN),
        )
        assert result is not EvaluationResult.MATCHED

    def test_unknown_does_not_become_compliant_either(self) -> None:
        # The mirror-image error, and the more dangerous one: silently
        # treating unknown as "fine" is hidden compliance.
        result = evaluate_condition(
            {"field": "mfa_enabled", "operator": "is_false"},
            a_resource(mfa_enabled=UNKNOWN),
        )
        assert result is not EvaluationResult.NOT_MATCHED

    def test_a_known_false_still_fires(self) -> None:
        # Regression guard: the fix must not suppress TRUE findings.
        result = evaluate_condition(
            {"field": "mfa_enabled", "operator": "is_false"},
            a_resource(mfa_enabled=False),
        )
        assert result is EvaluationResult.MATCHED

    def test_exists_is_matched_for_an_unknown_value(self) -> None:
        # The field IS present — the collector looked. That is a
        # different fact from a resource type that has no such attribute,
        # and conflating them would hide a permission problem.
        result = evaluate_condition(
            {"field": "mfa_enabled", "operator": "exists"}, a_resource(mfa_enabled=UNKNOWN)
        )
        assert result is EvaluationResult.MATCHED

    def test_an_absent_field_is_still_indeterminate(self) -> None:
        result = evaluate_condition(
            {"field": "never_collected", "operator": "is_false"}, a_resource(other=1)
        )
        assert result is EvaluationResult.INDETERMINATE

    def test_unknown_propagates_through_and(self) -> None:
        # Kleene: True AND Unknown = Unknown.
        result = evaluate_condition(
            {
                "and": [
                    {"field": "public", "operator": "is_true"},
                    {"field": "mfa_enabled", "operator": "is_false"},
                ]
            },
            a_resource(public=True, mfa_enabled=UNKNOWN),
        )
        assert result is EvaluationResult.INDETERMINATE

    def test_a_definite_false_still_short_circuits_and(self) -> None:
        # Kleene: False AND Unknown = False. The unknown does not
        # contaminate a decision already made.
        result = evaluate_condition(
            {
                "and": [
                    {"field": "public", "operator": "is_true"},
                    {"field": "mfa_enabled", "operator": "is_false"},
                ]
            },
            a_resource(public=False, mfa_enabled=UNKNOWN),
        )
        assert result is EvaluationResult.NOT_MATCHED

    def test_a_definite_true_short_circuits_or(self) -> None:
        # Kleene: True OR Unknown = True.
        result = evaluate_condition(
            {
                "or": [
                    {"field": "public", "operator": "is_true"},
                    {"field": "mfa_enabled", "operator": "is_false"},
                ]
            },
            a_resource(public=True, mfa_enabled=UNKNOWN),
        )
        assert result is EvaluationResult.MATCHED
