"""The Rule entity (blueprint §9), extended with CSPM catalog metadata
(Phase 3B design proposal, Part F).

``condition`` is kept as a raw ``dict`` rather than a typed recursive
model (ADR-004: avoids the fragility of a polymorphic recursive Union) —
it is validated lazily by :func:`domain.rules.conditions.evaluate_condition`
at evaluation time. The constructor only performs a light structural
check (must be a non-empty mapping) so an obviously-broken rule fails
fast at load time rather than at first evaluation.

Every field added in this phase is additive with a default value —
every ``Rule(...)`` call site from Phase 1/2/3 continues to work
unmodified; only rules that want the richer catalog metadata (the new
rule catalog in ``rules/aws/``) populate it.

``framework``/``control_id`` (singular, required, unchanged since Phase
1) remain the primary framework mapping — they are what feeds
``Finding.framework``/``Finding.control_id``, which in turn are exactly
the fields the AI Core's external contract expects
(``contracts.ai_service``, a real received handoff with singular
fields). ``framework_mappings`` (new, plural, optional) is *additional*
catalog-level detail for the CSPM conformance/documentation surface —
it does not replace or feed the AI contract path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping

from domain.resources.models import NormalizedResource
from domain.rules.conditions import EvaluationResult, evaluate_condition
from domain.rules.trace import RelationshipTrace
from domain.shared.enums import Confidence, Severity
from domain.shared.errors import InvalidRule, InvalidRuleCondition
from domain.shared.identifiers import ResourceId, RuleId

if TYPE_CHECKING:
    from domain.graph.models import ResourceGraph

#: Mapping statuses, in increasing order of claim strength.
#:
#: ``proposed`` was added in STEP 7. Before it, ``unresolved`` absorbed
#: two different statements — "we think this is right but nobody
#: checked" and "this is a deliberate technical proposal" — which are
#: not the same claim to an auditor.
MAPPING_VERIFIED = "verified"
MAPPING_PROPOSED = "proposed"
MAPPING_UNRESOLVED = "unresolved"

_VALID_MAPPING_STATUSES = frozenset(
    {MAPPING_VERIFIED, MAPPING_PROPOSED, MAPPING_UNRESOLVED}
)


@dataclass(frozen=True, slots=True)
class FrameworkMapping:
    """One additional (framework, control) reference for a ``Rule``,
    beyond its primary ``framework``/``control_id``.

    ``status`` defaults to ``"unresolved"`` deliberately — per the
    Phase 3B design proposal's anti-fabrication principle (§15/§23):
    fabricating an unverified control mapping is the single fastest way
    to lose credibility with an actual auditor. ``"verified"`` requires
    a rule catalog maintainer to have actually checked the mapping
    against the published framework/benchmark text.

    STEP 7 added two fields, both optional so every existing call site
    and every existing YAML rule keeps working:

    ``version``
        Which revision of the framework the control id belongs to.
        Without it a mapping is not auditable: CIS AWS Foundations
        v1.4.0 and v3.0.0 renumber controls, so ``cis_aws 1.20`` names
        different requirements depending on an edition nobody recorded.

    ``provenance``
        What the mapping was checked against. **Required when status is
        ``verified``** — a verified claim that cannot say *verified
        against what* is an assertion, not evidence. The audit found 11
        mappings claiming ``verified`` with no provenance anywhere in
        the model; they are downgraded rather than grandfathered,
        because grandfathering would preserve exactly the unfalsifiable
        claim this field exists to prevent.
    """

    framework: str
    control: str
    status: str = MAPPING_UNRESOLVED
    version: str | None = None
    provenance: str | None = None
    rationale: str | None = None

    def __post_init__(self) -> None:
        if not self.framework or not self.framework.strip():
            raise InvalidRule("FrameworkMapping.framework must be a non-blank string")
        if not self.control or not self.control.strip():
            raise InvalidRule("FrameworkMapping.control must be a non-blank string")
        if self.status not in _VALID_MAPPING_STATUSES:
            raise InvalidRule(
                f"FrameworkMapping.status must be one of {sorted(_VALID_MAPPING_STATUSES)}, got {self.status!r}"
            )
        for name in ("version", "provenance", "rationale"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise InvalidRule(
                    f"FrameworkMapping.{name} must be None or a non-blank string"
                )
        # The rule that makes `verified` mean something.
        if self.status == MAPPING_VERIFIED and not self.provenance:
            raise InvalidRule(
                f"FrameworkMapping to {self.framework}:{self.control} claims "
                "'verified' without provenance; a verified mapping must record "
                "what it was verified against"
            )


@dataclass(frozen=True, slots=True)
class Remediation:
    """Structured fix guidance for a ``Rule`` (Phase 3B design proposal,
    Part H): what's wrong, why it matters, how to fix it, and an
    optional non-destructive automation example (AWS CLI/Terraform
    snippet as plain text — never executed by this codebase, purely
    documentation surfaced in reports).
    """

    summary: str
    why_it_matters: str
    how_to_fix: str
    automation_example: str | None = None
    #: How the operator CONFIRMS the fix worked (§25). Optional for
    #: backward compatibility, but strongly encouraged: remediation
    #: guidance that cannot be verified is guidance nobody trusts, and
    #: "did that actually work?" is the first question after any change.
    verification: str | None = None

    def __post_init__(self) -> None:
        for name in ("summary", "why_it_matters", "how_to_fix"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidRule(f"Remediation.{name} must be a non-blank string")


@dataclass(frozen=True, slots=True)
class Rule:
    """A single compliance rule: a condition, its severity, and the
    catalog metadata a CSPM product needs beyond bare pass/fail logic.
    """

    id: RuleId
    framework: str
    control_id: str
    domain: str
    severity: Severity
    condition: Mapping[str, Any]

    # The resource type this rule applies to (e.g. "s3_bucket",
    # "azure_key_vault"). ``None`` means "every resource type", which
    # is the pre-existing behavior and therefore the default — no
    # Phase 1/2/3A call site changes.
    #
    # This exists because attribute names are NOT globally unique
    # across resource types: an Azure Key Vault and an Azure storage
    # account both carry `network_default_action`, so without scoping,
    # a Key Vault rule genuinely fires against storage accounts. (Found
    # by the conformance framework's own UNEXPECTED_FINDING
    # classification, not by inspection — see
    # docs/architecture/phase-3-conformance.md.)
    #
    # A rule that does not apply to a resource produces NO finding at
    # all, rather than INDETERMINATE: "this rule has nothing to say
    # about this resource type" is a different statement from "the data
    # needed to decide was not collected", and conflating them would
    # bury every real INDETERMINATE under thousands of irrelevant ones.
    applies_to_resource_type: str | None = None

    # Catalog metadata (Phase 3B) — all additive, all defaulted.
    version: str = "1.0.0"
    title: str = ""
    description: str = ""
    service: str = ""
    confidence: Confidence = Confidence.HIGH
    rationale: str = ""
    evidence_template: str = ""
    remediation: Remediation | None = None
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    framework_mappings: tuple[FrameworkMapping, ...] = ()

    # --- Additive metadata (CSPM upgrade §27/§28/§29). Every field is
    # optional so the 68 existing rules and their YAML load unchanged.

    #: Coarse grouping for catalog navigation ("access_control",
    #: "data_protection", "logging"). Distinct from `domain`, which is
    #: the risk domain used in scoring.
    category: str | None = None

    #: Plain-language statement of WHAT the rule looks at, for a reviewer
    #: deciding whether a finding is real. The condition tree is precise
    #: but not readable; this is the readable half.
    detection_logic: str | None = None

    #: Known-good situations that can still trigger this rule (§29). A
    #: public S3 bucket may legitimately be a website origin or a CDN
    #: source. Without this, a triager has to rediscover the same
    #: exception every time, and rules with high false-positive rates get
    #: switched off wholesale instead of tuned.
    false_positive_notes: str | None = None

    #: Whether an accepted-risk exception may be registered against this
    #: rule (§28). Defaults to True: most controls are legitimately
    #: waivable with justification. Set False for controls where a waiver
    #: would be meaningless or dangerous.
    exceptions_supported: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.id, RuleId):
            raise InvalidRule("id must be a RuleId")
        for name in ("framework", "control_id", "domain"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidRule(f"{name} must be a non-blank string")
        if not isinstance(self.severity, Severity):
            raise InvalidRule("severity must be a Severity")
        if not isinstance(self.condition, Mapping) or not self.condition:
            raise InvalidRuleCondition("condition must be a non-empty mapping")
        if self.applies_to_resource_type is not None and (
            not isinstance(self.applies_to_resource_type, str) or not self.applies_to_resource_type.strip()
        ):
            raise InvalidRule("applies_to_resource_type must be None or a non-blank string")
        if not isinstance(self.version, str) or not self.version.strip():
            raise InvalidRule("version must be a non-blank string")
        if not isinstance(self.confidence, Confidence):
            raise InvalidRule("confidence must be a Confidence")
        if self.remediation is not None and not isinstance(self.remediation, Remediation):
            raise InvalidRule("remediation must be a Remediation instance or None")
        for mapping in self.framework_mappings:
            if not isinstance(mapping, FrameworkMapping):
                raise InvalidRule("framework_mappings must contain only FrameworkMapping instances")

        object.__setattr__(self, "condition", MappingProxyType(dict(self.condition)))

    def applies_to(self, resource: NormalizedResource) -> bool:
        """Whether this rule has anything to say about ``resource``.

        ``True`` for every resource when ``applies_to_resource_type`` is
        ``None`` (the default), preserving the original
        every-rule-against-every-resource behavior.
        """

        if self.applies_to_resource_type is None:
            return True
        return resource.resource_type == self.applies_to_resource_type

    def evaluate(
        self,
        resource: NormalizedResource,
        *,
        graph: "ResourceGraph | None" = None,
        resources_by_id: Mapping[ResourceId, NormalizedResource] | None = None,
        as_of: datetime | None = None,
        trace: "RelationshipTrace | None" = None,
    ) -> EvaluationResult:
        """Evaluate this rule's condition against a resource.
        Deterministic: the same rule, resource, graph snapshot, and
        ``as_of`` always yield the same result.

        ``graph``/``resources_by_id`` are only required if ``condition``
        contains a ``relationship`` node; ``as_of`` is only required if
        it uses a temporal operator (``age_gt_days`` and friends) — see
        ``domain.rules.conditions`` for the full contract. All three
        default to ``None``, so existing single-resource rules are
        unaffected.

        ``trace`` is an optional sink recording which graph neighbours
        the condition examined — what lets a cross-resource finding name
        the resource it matched rather than only assert one exists.
        """

        return evaluate_condition(self.condition, resource, graph=graph, resources_by_id=resources_by_id, as_of=as_of, trace=trace)
