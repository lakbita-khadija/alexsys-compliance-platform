"""``EvaluateRules`` (blueprint §4), extended for cross-resource
evaluation and finding-identity (Phase 3B design proposal, Parts C/D/I).

Orchestrates rule evaluation: obtains the rule catalog through
``LoadRuleCatalog``, evaluates every rule against every resource using
the Domain's own ``Rule.evaluate()`` (never reimplementing condition
logic — this class still contains zero rule-condition logic itself),
and constructs ``Finding`` entities from the results.

Design decisions (documented rather than left implicit — see
docs/architecture/phase-2-application.md and phase-3-rules.md):

* ``EvaluationResult -> FindingStatus`` mapping is the 1:1 convention
  Phase 1's own docs anticipated (``MATCHED -> FAIL``,
  ``NOT_MATCHED -> PASS``, ``INDETERMINATE -> INDETERMINATE``).
* A ``Finding`` is created for every ``(rule, resource)`` pair,
  including passes — a PASS is evidence, not silence.
* ``graph`` (optional, an already-built ``ResourceGraph``) and a
  ``resources_by_id`` lookup (built once, internally, from the same
  ``resources`` iterable already passed in) are threaded into
  ``Rule.evaluate()`` so ``relationship`` conditions can resolve
  neighbors — this is what actually activates the graph-aware DSL
  (domain.rules.conditions) added this phase. Omitting ``graph`` is
  safe: any rule without a ``relationship`` node is unaffected.
* ``as_of`` for temporal operators (``age_gt_days`` and friends) is
  ``detected_at`` — the scan's own timestamp, not a second parameter
  with an overlapping meaning and not a hidden ``datetime.now()`` call.
* Finding identity is now two-tier (Part I): ``logical_finding_id`` is
  stable across repeated scans (``tenant:account:resource:rule``);
  ``Finding.id`` is scan-scoped (``logical_finding_id:scan_id``) and
  therefore *not* stable across scans by design — see
  docs/architecture/phase-3-rules.md for why.
* ``rule.version`` now populates ``Finding.rule_version`` — the field
  existed since Phase 1 but nothing wrote to it, since ``Rule`` itself
  had no version concept before this phase.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Iterable

from application.rules.evidence import render_evidence
from application.rules.rule_catalog import LoadRuleCatalog
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.graph.validation import graph_context_for
from domain.resources.models import NormalizedResource
from domain.rules.conditions import EvaluationResult
from domain.rules.rule import Rule
from domain.rules.trace import RelationshipTrace
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId, account_key
from domain.tenants.isolation import ensure_same_tenant

if TYPE_CHECKING:
    from domain.graph.models import ResourceGraph

_STATUS_BY_RESULT = {
    EvaluationResult.MATCHED: FindingStatus.FAIL,
    EvaluationResult.NOT_MATCHED: FindingStatus.PASS,
    EvaluationResult.INDETERMINATE: FindingStatus.INDETERMINATE,
}


class EvaluateRules:
    """Evaluates the rule catalog against a set of resources, producing
    ``Finding``s.
    """

    def __init__(self, rule_catalog: LoadRuleCatalog) -> None:
        self._rule_catalog = rule_catalog

    def evaluate(
        self,
        *,
        tenant_id: TenantId,
        resources: Iterable[NormalizedResource],
        detected_at: datetime,
        scan_id: str | None = None,
        rule_ids: tuple[RuleId, ...] | None = None,
        graph: "ResourceGraph | None" = None,
    ) -> tuple[Finding, ...]:
        rules = self._rule_catalog.load()
        if rule_ids is not None:
            wanted = set(rule_ids)
            rules = tuple(rule for rule in rules if rule.id in wanted)

        resources = tuple(resources)
        resources_by_id: dict[ResourceId, NormalizedResource] = {r.resource_id: r for r in resources}

        findings: list[Finding] = []
        for resource in resources:
            ensure_same_tenant(tenant_id, resource.tenant_id, context="rule evaluation")
            for rule in rules:
                # A rule scoped to another resource type has nothing to
                # say about this resource — skip it entirely rather than
                # emitting an INDETERMINATE finding. See
                # `Rule.applies_to_resource_type` for why the two are
                # deliberately different outcomes.
                if not rule.applies_to(resource):
                    continue
                findings.append(
                    self._to_finding(
                        rule=rule,
                        resource=resource,
                        tenant_id=tenant_id,
                        detected_at=detected_at,
                        scan_id=scan_id,
                        graph=graph,
                        resources_by_id=resources_by_id,
                    )
                )

        return tuple(findings)

    @staticmethod
    def _to_finding(
        *,
        rule: Rule,
        resource: NormalizedResource,
        tenant_id: TenantId,
        detected_at: datetime,
        scan_id: str | None,
        graph: "ResourceGraph | None",
        resources_by_id: dict[ResourceId, NormalizedResource],
    ) -> Finding:
        trace = RelationshipTrace()
        result = rule.evaluate(
            resource,
            graph=graph,
            resources_by_id=resources_by_id,
            as_of=detected_at,
            trace=trace,
        )

        # `account` is an explicit sentinel rather than `None`'s repr. The
        # original `{resource.account_id!s}` rendered a missing account as
        # the literal "None", so two DIFFERENT accounts whose id could not
        # be resolved produced the SAME logical_finding_id — merging two
        # accounts' security history onto one lifecycle row. Verified and
        # documented in docs/architecture/phase-4-persistence-audit.md §3.
        #
        # The sentinel does not make those two accounts distinguishable
        # (nothing here can), but it is honest about being unknown instead
        # of masquerading as a real value. Phase 4 stores the identity
        # COMPONENTS as columns and keys the lifecycle on those, so it is
        # never exposed to this ambiguity — and it treats this string as
        # opaque, since `:` also appears inside ARNs and makes it
        # unparseable.
        account = account_key(resource.account_id)
        logical_finding_id = f"{tenant_id!s}:{account}:{resource.resource_id!s}:{rule.id!s}"
        finding_id = f"{logical_finding_id}:{scan_id!s}"

        evidence_data = dict(resource.attributes)
        narrative = render_evidence(rule.evidence_template, resource)
        if narrative:
            evidence_data = {**evidence_data, "narrative": narrative}

        return Finding(
            id=FindingId(finding_id),
            tenant_id=tenant_id,
            resource_id=resource.resource_id,
            rule_id=rule.id,
            framework=rule.framework,
            control_id=rule.control_id,
            domain=rule.domain,
            status=_STATUS_BY_RESULT[result],
            severity=rule.severity,
            evidence=Evidence(data=evidence_data),
            detected_at=detected_at,
            scan_id=scan_id,
            region=resource.region,
            rule_version=rule.version,
            account_id=resource.account_id,
            logical_finding_id=logical_finding_id,
            # Contextualization (expansion §3). Populated ONLY from what
            # the rule actually traversed, never from the resource's
            # whole neighbourhood — a finding that names resources it did
            # not consider is worse than one that names none, because a
            # responder will go investigate them.
            related_resources=trace.matched_resource_ids,
            indeterminate_resources=trace.indeterminate_resource_ids,
            graph_context=(
                graph_context_for(graph, resource.resource_id)
                if trace.traversed and graph is not None
                else None
            ),
        )
