"""Deriving identity → resource access edges from policy grants.

## The problem this module exists to *not* create

An IAM policy saying `Action: "s3:*"` on `Resource: "*"` grants access to
every bucket in the account. The naive graph reaction is to emit an edge
from that role to every collected bucket.

That is wrong in two independent ways:

**It explodes the graph.** One role × 500 buckets = 500 edges. Ten such
roles = 5000. Path-finding over that is quadratic in something the
customer cannot control, and the attack path analyzer's `MAX_DEPTH`
budget is spent walking noise.

**It destroys the signal.** If a role reaches everything, "this role can
reach the sensitive bucket" stops distinguishing anything. The finding
that mattered — *this specific role can read this specific data* — is
buried under 499 that do not.

So a wildcard grant produces **no per-resource edges at all**. It is
recorded as a property of the identity, which is what it actually is:
*this role has unconstrained access*, one fact about one resource, not
500 relationships.

## Evidence levels

| Level | Pattern | Edge? |
|---|---|---|
| `EXACT` | Names the resource literally | ✅ high confidence |
| `BROAD` | Wildcard with a real literal prefix (`acme-*`) | ✅ medium confidence |
| `POTENTIAL` | Unconstrained (`*`, `arn:aws:s3:::*`) | ❌ recorded on the identity |
| `UNKNOWN` | Policies could not be read | ❌ nothing asserted |

The `POTENTIAL` row is the important one, and the reason this is a
four-value vocabulary rather than a boolean: "this role probably reaches
that bucket" is a real state, and the honest representation of it is
*not an edge*.

## What this module is not

It does **not** evaluate conditions. `aws:SourceIp`, `aws:PrincipalOrgID`
and friends can make an apparently broad grant narrow, and evaluating
them requires request context that a scanner does not have. A conditioned
grant therefore has its confidence **downgraded** rather than being
dropped or trusted — see :func:`derive_access_edges`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from domain.shared.identifiers import ResourceId


class AccessEvidence:
    """How strongly a policy grant implies access to a specific resource."""

    EXACT = "exact"
    BROAD = "broad"
    POTENTIAL = "potential"
    UNKNOWN = "unknown"


#: Confidence carried by an edge, per evidence level. Reuses the graph
#: vocabulary — a fifth confidence system would be the mistake.
_CONFIDENCE_BY_EVIDENCE: Mapping[str, str] = {
    AccessEvidence.EXACT: "high",
    AccessEvidence.BROAD: "medium",
}

#: One step down, applied when a grant carries a condition we cannot
#: evaluate. Not dropped — the access may well be real — and not trusted
#: at full strength either.
_DOWNGRADE: Mapping[str, str] = {"high": "medium", "medium": "low", "low": "low"}

#: Minimum literal characters before the first wildcard for a pattern to
#: be considered constrained. One is enough: `acme-*` genuinely narrows
#: an account's buckets, while `*` narrows nothing.
_MIN_LITERAL_PREFIX = 1


@dataclass(frozen=True, slots=True)
class AccessGrant:
    """One policy statement, reduced to what edge derivation needs.

    Provider-agnostic on purpose: the collector flattens AWS statements
    into this shape, so the domain never learns what an ARN is beyond
    "a string that may contain wildcards".
    """

    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    has_condition: bool = False
    condition_keys: tuple[str, ...] = ()
    #: Present when the statement used `NotResource` — "everything
    #: except". Treated as unconstrained, because the complement of a
    #: finite list is everything else.
    inverted_resources: bool = False

    @property
    def is_allow(self) -> bool:
        return self.effect.lower() == "allow"

    @property
    def is_deny(self) -> bool:
        return self.effect.lower() == "deny"


@dataclass(frozen=True, slots=True)
class DerivedAccess:
    """One identity → resource edge the graph should carry."""

    target: ResourceId
    evidence: str
    confidence: str
    matched_pattern: str
    matched_actions: tuple[str, ...]
    conditioned: bool


def _literal_prefix(pattern: str) -> str:
    """Everything before the first wildcard."""

    for index, char in enumerate(pattern):
        if char in "*?":
            return pattern[:index]
    return pattern


def _resource_part(pattern: str) -> str:
    """The resource-specific tail of an ARN-shaped pattern.

    `arn:aws:s3:::acme-reports` → `acme-reports`. Needed because
    collected resource ids are not uniformly ARNs — an S3 bucket's id is
    its name, while an IAM role's id is its ARN — so a pattern must be
    comparable against both forms.
    """

    if not pattern.startswith("arn:"):
        return pattern
    parts = pattern.split(":", 5)
    return parts[5] if len(parts) == 6 else pattern


def pattern_matches(pattern: str, value: str) -> bool:
    """Glob match, case-insensitive, anchored.

    Deliberately generic: `*` and `?` are the only metacharacters, which
    is what IAM uses, and nothing here is AWS-specific.
    """

    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(escaped, value, flags=re.IGNORECASE) is not None


def _candidate_forms(pattern: str) -> tuple[str, ...]:
    """The forms of a pattern that might match a collected resource id.

    Three, because id conventions differ by resource type:

    - the whole pattern (an IAM role's id *is* its ARN)
    - its resource part (an S3 bucket's id is its bare name)
    - its resource part truncated at the first `/`, so an object-level
      grant `acme-reports/*` still identifies the bucket `acme-reports`
    """

    forms = [pattern]
    resource_part = _resource_part(pattern)
    if resource_part != pattern:
        forms.append(resource_part)
    head = resource_part.split("/", 1)[0]
    if head and head != resource_part:
        forms.append(head)
    return tuple(dict.fromkeys(forms))


def classify_pattern(pattern: str) -> str:
    """The evidence level a resource pattern can support on its own."""

    if not pattern or pattern == "*":
        return AccessEvidence.POTENTIAL
    if "*" not in pattern and "?" not in pattern:
        return AccessEvidence.EXACT

    # A wildcard is only meaningful if something literal constrains it.
    # `arn:aws:s3:::*` has an ARN prefix but no resource-level
    # constraint, so it selects every bucket — indistinguishable from
    # `*` for our purposes.
    resource_part = _resource_part(pattern)
    if len(_literal_prefix(resource_part)) >= _MIN_LITERAL_PREFIX:
        return AccessEvidence.BROAD
    return AccessEvidence.POTENTIAL


def _grant_matches_resource(grant: AccessGrant, resource_id: str) -> tuple[bool, str, str]:
    """``(matched, evidence, pattern)`` for one grant against one resource."""

    if grant.inverted_resources:
        # NotResource is "everything except these". We do not attempt to
        # enumerate the complement.
        return False, AccessEvidence.POTENTIAL, "*"

    best: tuple[bool, str, str] = (False, AccessEvidence.POTENTIAL, "")
    for pattern in grant.resources:
        evidence = classify_pattern(pattern)
        if evidence == AccessEvidence.POTENTIAL:
            best = (False, AccessEvidence.POTENTIAL, pattern) if not best[0] else best
            continue
        if any(pattern_matches(form, resource_id) for form in _candidate_forms(pattern)):
            if evidence == AccessEvidence.EXACT:
                return True, evidence, pattern
            best = (True, evidence, pattern)
    return best


def has_unconstrained_access(grants: Iterable[AccessGrant]) -> bool:
    """Whether any ALLOW grant reaches resources without constraint.

    This is what replaces the edges a wildcard would otherwise produce.
    """

    return any(
        grant.is_allow
        and (
            grant.inverted_resources
            or any(classify_pattern(p) == AccessEvidence.POTENTIAL for p in grant.resources)
        )
        for grant in grants
    )


def derive_access_edges(
    grants: Sequence[AccessGrant],
    candidate_resource_ids: Iterable[ResourceId],
) -> tuple[DerivedAccess, ...]:
    """Edges from one identity to the resources its policies name.

    Explicit `Deny` wins, as it does in AWS: a resource reached by an
    ALLOW and also covered by a DENY produces **no edge**. Getting that
    backwards would report access the principal does not have — the
    single most consequential IAM evaluation mistake.

    Results are sorted, so two scans over the same policies produce the
    same edges in the same order.
    """

    allows = [g for g in grants if g.is_allow]
    denies = [g for g in grants if g.is_deny]
    if not allows:
        return ()

    derived: list[DerivedAccess] = []
    for resource_id in candidate_resource_ids:
        value = str(resource_id)

        # Deny first — an allowed-then-denied resource must not appear.
        if any(_grant_matches_resource(deny, value)[0] for deny in denies):
            continue

        best: DerivedAccess | None = None
        for grant in allows:
            matched, evidence, pattern = _grant_matches_resource(grant, value)
            if not matched:
                continue
            confidence = _CONFIDENCE_BY_EVIDENCE[evidence]
            if grant.has_condition:
                confidence = _DOWNGRADE[confidence]
            candidate = DerivedAccess(
                target=resource_id,
                evidence=evidence,
                confidence=confidence,
                matched_pattern=pattern,
                matched_actions=tuple(sorted(grant.actions)),
                conditioned=grant.has_condition,
            )
            # Strongest evidence wins: an EXACT grant beats a BROAD one
            # for the same resource.
            if best is None or (
                candidate.evidence == AccessEvidence.EXACT
                and best.evidence != AccessEvidence.EXACT
            ):
                best = candidate
        if best is not None:
            derived.append(best)

    return tuple(sorted(derived, key=lambda d: str(d.target)))


def grants_from_mappings(raw: Any) -> tuple[AccessGrant, ...]:
    """Rebuild grants from the plain mappings a collector stored.

    Collectors cannot put domain objects into ``attributes`` — that
    mapping crosses into persistence and the AI contract — so grants
    travel as dicts and are rehydrated here.
    """

    if not isinstance(raw, (list, tuple)):
        return ()
    grants: list[AccessGrant] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        grants.append(
            AccessGrant(
                effect=str(item.get("effect", "")),
                actions=tuple(str(a) for a in item.get("actions", ())),
                resources=tuple(str(r) for r in item.get("resources", ())),
                has_condition=bool(item.get("has_condition", False)),
                condition_keys=tuple(str(k) for k in item.get("condition_keys", ())),
                inverted_resources=bool(item.get("inverted_resources", False)),
            )
        )
    return tuple(grants)


__all__ = [
    "AccessEvidence",
    "AccessGrant",
    "DerivedAccess",
    "classify_pattern",
    "derive_access_edges",
    "grants_from_mappings",
    "has_unconstrained_access",
    "pattern_matches",
]
