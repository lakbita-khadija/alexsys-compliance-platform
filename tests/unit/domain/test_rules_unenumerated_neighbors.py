"""Type-filtered traversal across a neighbour nobody enumerated.

Found while adding the ``ec2_instance -> aws_subnet`` edge in STEP 8A.1,
and not caused by it: the defect had been live in every ``target_type``
filtered rule since the DSL gained relationship conditions.

``target_type`` was applied as a plain ``resource_type != target`` drop.
That is correct for a *collected* node — there the type is an
observation and the mismatch is a fact. It is wrong for an **external**
one. An external node exists only because a collector pointed at
something and nothing enumerated it; ``BuildResourceGraph`` gives it the
placeholder type ``external_resource`` precisely because the id prefix
is not evidence of a type. Dropping it on a type mismatch asserts "this
is not a security group", which is exactly what the scan does not know.

The consequences run in both directions, and both are the failure this
codebase refuses everywhere else:

* ``relationship`` — zero neighbours survive the filter, which is
  vacuously NOT_MATCHED, reported as **PASS**. An instance whose only
  attachment was never collected reads as *confirmed compliant*.
* ``no_relationship`` — the same zero reads as "the relationship is
  absent", reported as a **violation**. A database whose private
  endpoint was never collected reads as *confirmed unprotected*.

The fix folds unenumerated neighbours in as ``INDETERMINATE``
contributors rather than dropping them. Under Kleene OR a confirmed
violation still wins, so no finding is suppressed — the tests below pin
that, because a fix that silenced real findings would be worse than the
bug.
"""

from __future__ import annotations

from datetime import datetime, timezone

from application.graph.build_resource_graph import BuildResourceGraph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.rules.conditions import EvaluationResult, evaluate_condition
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId, TenantId

MATCHED = EvaluationResult.MATCHED
NOT_MATCHED = EvaluationResult.NOT_MATCHED
INDETERMINATE = EvaluationResult.INDETERMINATE

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

OPEN_SG = {
    "relationship": "attached_to",
    "direction": "outgoing",
    "target_type": "security_group",
    "where": {"field": "has_unrestricted_ingress", "operator": "is_true"},
}


def resource(rid, rtype, attributes=None, attached=()):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=tuple(
            ResourceRelationship(
                target_resource_id=ResourceId(t),
                relationship_type=RelationshipType.ATTACHED_TO,
            )
            for t in attached
        ),
        collected_at=NOW,
    )


def evaluate(condition, subject, resources):
    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    return evaluate_condition(
        condition,
        subject,
        graph=graph,
        resources_by_id={r.resource_id: r for r in resources},
    )


def sg(rid, *, open_ingress):
    return resource(rid, "security_group", {"has_unrestricted_ingress": open_ingress})


class TestExistenceQuantifiedTraversal:
    def test_an_uncollected_attachment_is_indeterminate_not_a_pass(self) -> None:
        # The bug, stated directly. Nothing named sg-1 was collected, so
        # whether it is an open security group is unknown.
        instance = resource("i-1", "ec2_instance", attached=["sg-1"])
        assert evaluate(OPEN_SG, instance, [instance]) is INDETERMINATE

    def test_a_collected_safe_neighbour_still_passes(self) -> None:
        # The fix must not turn every clean result into INDETERMINATE.
        instance = resource("i-1", "ec2_instance", attached=["sg-1"])
        resources = [instance, sg("sg-1", open_ingress=False)]
        assert evaluate(OPEN_SG, instance, resources) is NOT_MATCHED

    def test_a_collected_open_neighbour_still_fails(self) -> None:
        instance = resource("i-1", "ec2_instance", attached=["sg-1"])
        resources = [instance, sg("sg-1", open_ingress=True)]
        assert evaluate(OPEN_SG, instance, resources) is MATCHED

    def test_a_confirmed_violation_beats_an_unknown_neighbour(self) -> None:
        # The load-bearing property of routing unknowns through Kleene
        # OR: a real finding must not be downgraded to "we cannot tell"
        # because some unrelated attachment was not collected.
        instance = resource("i-1", "ec2_instance", attached=["sg-1", "sg-2"])
        resources = [instance, sg("sg-1", open_ingress=True)]
        assert evaluate(OPEN_SG, instance, resources) is MATCHED

    def test_a_safe_neighbour_plus_an_unknown_one_is_indeterminate(self) -> None:
        # The other half: "one group is fine and we could not read the
        # other" is not "this instance is fine".
        instance = resource("i-1", "ec2_instance", attached=["sg-1", "sg-2"])
        resources = [instance, sg("sg-1", open_ingress=False)]
        assert evaluate(OPEN_SG, instance, resources) is INDETERMINATE

    def test_a_collected_neighbour_of_another_type_is_still_dropped(self) -> None:
        # The boundary of the fix. A collected subnet IS known not to be
        # a security group, so it must not make the rule indeterminate —
        # otherwise the new STEP 8A.1 placement edge would poison every
        # security group rule in the catalog.
        instance = resource("i-1", "ec2_instance", attached=["sg-1", "subnet-1"])
        resources = [
            instance,
            sg("sg-1", open_ingress=False),
            resource("subnet-1", "aws_subnet", {"vpc_id": "vpc-1"}),
        ]
        assert evaluate(OPEN_SG, instance, resources) is NOT_MATCHED

    def test_no_attachments_at_all_is_still_vacuously_not_matched(self) -> None:
        instance = resource("i-1", "ec2_instance")
        assert evaluate(OPEN_SG, instance, [instance]) is NOT_MATCHED

    def test_an_untyped_traversal_is_unaffected(self) -> None:
        # Without `target_type` there is no filter to be wrong about;
        # an unenumerated neighbour was already INDETERMINATE via the
        # missing-NormalizedResource branch.
        condition = {
            "relationship": "attached_to",
            "direction": "outgoing",
            "where": {"field": "has_unrestricted_ingress", "operator": "is_true"},
        }
        instance = resource("i-1", "ec2_instance", attached=["sg-1"])
        assert evaluate(condition, instance, [instance]) is INDETERMINATE


class TestAbsenceQuantifiedTraversal:
    """The inverted failure mode: an unknown inventing a violation."""

    CONDITION = {
        "no_relationship": "attached_to",
        "direction": "outgoing",
        "target_type": "security_group",
        "requires_collected": "security_group",
    }

    def test_an_uncollected_attachment_does_not_become_an_absence(self) -> None:
        # A security group WAS collected elsewhere, so the coverage guard
        # passes and cannot save us here — this instance's own attachment
        # is the unknown. Before the fix this returned MATCHED: a
        # fabricated "this instance has no security group" violation.
        instance = resource("i-1", "ec2_instance", attached=["sg-unknown"])
        resources = [instance, sg("sg-other", open_ingress=False)]
        assert evaluate(self.CONDITION, instance, resources) is INDETERMINATE

    def test_a_genuine_absence_is_still_reported(self) -> None:
        # The fix must not disarm the absence rule it protects.
        instance = resource("i-1", "ec2_instance")
        resources = [instance, sg("sg-other", open_ingress=False)]
        assert evaluate(self.CONDITION, instance, resources) is MATCHED

    def test_a_present_attachment_still_refutes_the_absence(self) -> None:
        instance = resource("i-1", "ec2_instance", attached=["sg-1"])
        resources = [instance, sg("sg-1", open_ingress=False)]
        assert evaluate(self.CONDITION, instance, resources) is NOT_MATCHED

    def test_the_coverage_guard_still_wins_over_everything(self) -> None:
        # No security group collected anywhere: INDETERMINATE regardless,
        # checked before any edge counting. Unchanged by this fix.
        instance = resource("i-1", "ec2_instance", attached=["sg-1"])
        assert evaluate(self.CONDITION, instance, [instance]) is INDETERMINATE

    def test_a_collected_neighbour_of_another_type_still_yields_absence(self) -> None:
        # An instance attached only to a collected subnet genuinely has
        # no security group edge.
        instance = resource("i-1", "ec2_instance", attached=["subnet-1"])
        resources = [
            instance,
            resource("subnet-1", "aws_subnet", {"vpc_id": "vpc-1"}),
            sg("sg-other", open_ingress=False),
        ]
        assert evaluate(self.CONDITION, instance, resources) is MATCHED
