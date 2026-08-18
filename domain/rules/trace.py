"""Traversal trace for cross-resource rule evaluation (expansion §3).

Today a cross-resource finding says *"EC2 instance attached to an open
security group"* without naming **which** security group. The rule walked
the edge, decided, and threw the traversal away — so the one piece of
information a security engineer needs in order to act is exactly the
piece that is missing.

That is what this module fixes. ``RelationshipTrace`` is an optional sink
the evaluator writes to while it traverses; when a caller supplies one,
it comes back knowing which neighbours were examined and what each
contributed.

**Why a sink instead of a richer return type.** ``evaluate_condition``
returns an ``EvaluationResult`` and is called recursively from a dozen
places. Threading a (result, trace) pair through every branch would touch
every node type to serve two of them. An optional sink is additive:
callers that pass nothing get byte-identical behaviour, and the evaluator
stays a function of its inputs.

**Determinism is preserved.** Observations are appended in traversal
order, and traversal order is the graph's index order, which is sorted.
The trace does not read a clock, generate an id, or consult anything
outside the arguments it is given — the same rule over the same graph
records the same observations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from domain.shared.enums import RelationshipType
from domain.shared.identifiers import ResourceId


@dataclass(frozen=True, slots=True)
class RelationshipObservation:
    """One neighbour examined by one relationship condition."""

    relationship_type: RelationshipType
    direction: Literal["outgoing", "incoming"]
    neighbor_id: ResourceId
    neighbor_type: str
    #: ``True`` when this neighbour satisfied the condition's ``where``
    #: clause, ``False`` when it did not, ``None`` when the answer was
    #: indeterminate — the same three-valued distinction the evaluator
    #: makes, kept rather than flattened, because "we could not read this
    #: neighbour" is a different report from "this neighbour was fine".
    satisfied: bool | None

    #: ``True`` when the observation was recorded by an absence
    #: (``no_relationship``) condition. The neighbour's meaning inverts
    #: there: it is a reason the requirement was **met**, not a reason
    #: the rule fired.
    from_absence_check: bool = False


@dataclass(slots=True)
class RelationshipTrace:
    """Collects observations during one rule evaluation.

    Mutable by design — it is a recorder, not a value. One trace per
    (rule, resource) evaluation; reusing one across resources would
    attribute one resource's neighbours to another.
    """

    observations: list[RelationshipObservation] = field(default_factory=list)

    def record(self, observation: RelationshipObservation) -> None:
        self.observations.append(observation)

    @property
    def matched_resource_ids(self) -> tuple[str, ...]:
        """Neighbours that satisfied an existence condition's ``where``.

        This is the set a finding names as *related*: the resources whose
        state is part of why the rule reached its conclusion.

        Absence observations are excluded. Under ``no_relationship`` a
        satisfying neighbour is evidence the control was **met**, so
        listing it beside a violation would name a resource as implicated
        in a finding it in fact prevented.

        Deduplicated and sorted — two conditions traversing the same
        neighbour describe one related resource, and a finding whose
        related list reorders between scans cannot be diffed.
        """

        return tuple(
            sorted(
                {
                    str(o.neighbor_id)
                    for o in self.observations
                    if o.satisfied is True and not o.from_absence_check
                }
            )
        )

    @property
    def indeterminate_resource_ids(self) -> tuple[str, ...]:
        """Neighbours whose contribution could not be determined.

        Kept separate from ``matched_resource_ids`` so a data gap is
        never presented as a confirmed relationship — the whole point of
        three-valued evaluation, carried into the finding's context.
        """

        return tuple(sorted({str(o.neighbor_id) for o in self.observations if o.satisfied is None}))

    @property
    def traversed(self) -> bool:
        """Whether any relationship condition ran at all.

        Distinguishes "this rule is cross-resource and found nothing"
        from "this rule never looked" — which decides whether a finding
        carries graph context or not. Attaching a neighbourhood to every
        single-resource finding would bloat every row for no signal.
        """

        return bool(self.observations)


__all__ = ["RelationshipObservation", "RelationshipTrace"]
