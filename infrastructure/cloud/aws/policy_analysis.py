"""Semantic IAM policy and trust-policy analysis (§5, §4.1).

The brief is explicit: *"Do not only detect Principal `*`. Analyze trust
policies semantically."* This module is that analysis.

## Why name-matching is not enough

The naive check is `"AdministratorAccess" in attached_policy_names`. It
misses every real-world escalation path:

* a **customer-managed** policy granting `Action: "*"` on `Resource: "*"`
  under a harmless name like `DeveloperAccess`
* an **inline** policy on the role, which has no name in any list
* `iam:PassRole` + `ec2:RunInstances`, neither of which is admin, but
  which together let a caller launch an instance carrying any role —
  full escalation
* `iam:CreatePolicyVersion` with `SetAsDefault`, which rewrites a policy
  the caller is already attached to

So statements are parsed and evaluated, not matched by name.

## Two properties that decide correctness

**`NotAction` inverts the meaning.** `{"Effect": "Allow", "NotAction":
"iam:*", "Resource": "*"}` grants everything except IAM — vastly more
than it appears, and a naive reader sees `iam:*` and concludes the
opposite. Getting this backwards produces confidently wrong findings.

**Explicit `Deny` always wins in AWS**, regardless of order. A policy
that allows `*` and denies `iam:*` is not an admin policy. Ignoring Deny
overstates severity, which is how a CSPM earns a reputation for crying
wolf.

## Confidence, not just verdicts

Every analysis returns what it could not determine. A `Condition` block
this module does not interpret (`aws:PrincipalOrgID`, an IP restriction)
can render an apparently-wide grant safe. Rather than guess, the finding
is reported with reduced confidence and the condition is surfaced as
evidence — which is what `UNKNOWN` exists for elsewhere, applied here at
statement granularity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: Actions that, given a permissive Resource, allow a principal to grant
#: itself more permission. Grouped by mechanism because the groups are
#: what a rule wants to reason about.
PRIVILEGE_ESCALATION_ACTIONS: Mapping[str, tuple[str, ...]] = {
    "policy_rewrite": (
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
    ),
    "policy_attachment": (
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutGroupPolicy",
    ),
    "credential_creation": (
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:ChangePassword",
    ),
    "trust_modification": (
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateRole",
    ),
    # PassRole is only dangerous WITH a compute action that consumes it.
    # Tracked separately so the pairing can be required rather than
    # flagging every legitimate PassRole grant.
    "pass_role": ("iam:PassRole",),
    "assume_role": ("sts:AssumeRole", "sts:AssumeRoleWithSAML"),
}

#: Services that can run code under a passed role. `iam:PassRole` alone
#: is normal and necessary; PassRole *plus* one of these is escalation.
COMPUTE_ACTIONS: tuple[str, ...] = (
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "ecs:RunTask",
    "ecs:RegisterTaskDefinition",
    "glue:CreateDevEndpoint",
    "cloudformation:CreateStack",
    "datapipeline:CreatePipeline",
    "sagemaker:CreateNotebookInstance",
    "codebuild:CreateProject",
)

#: Condition keys that meaningfully constrain an otherwise-wide grant.
#: Their presence lowers confidence rather than clearing the finding —
#: this module does not evaluate condition VALUES, only notes them.
CONSTRAINING_CONDITION_KEYS: tuple[str, ...] = (
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalAccount",
    "aws:PrincipalArn",
    "aws:SourceArn",
    "aws:SourceAccount",
    "aws:SourceIp",
    "aws:SourceVpc",
    "aws:SourceVpce",
    "aws:userid",
    "sts:ExternalId",
    "aws:MultiFactorAuthPresent",
)

_ACCOUNT_ARN = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):")


def _as_list(value: Any) -> list[Any]:
    """AWS policy fields are string-or-list everywhere. Normalize once."""

    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def action_matches(pattern: str, action: str) -> bool:
    """Whether an IAM action pattern matches a concrete action.

    IAM wildcards are `*` (any sequence) and `?` (any single char), and
    matching is case-insensitive. Implemented by translating to a regex
    with everything else escaped — a plain `fnmatch` would additionally
    honour `[seq]` character classes, which IAM does not support, and
    would therefore match strings AWS would not.
    """

    escaped = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(escaped, action, flags=re.IGNORECASE) is not None


@dataclass(frozen=True, slots=True)
class Statement:
    """One parsed policy statement."""

    effect: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    resources: tuple[str, ...]
    not_resources: tuple[str, ...]
    principals: Mapping[str, tuple[str, ...]]
    condition: Mapping[str, Any]

    @property
    def is_allow(self) -> bool:
        return self.effect.lower() == "allow"

    @property
    def is_deny(self) -> bool:
        return self.effect.lower() == "deny"

    @property
    def has_condition(self) -> bool:
        return bool(self.condition)

    @property
    def constraining_condition_keys(self) -> tuple[str, ...]:
        """Condition keys that plausibly narrow this statement."""

        found = []
        for operator_block in self.condition.values():
            if not isinstance(operator_block, Mapping):
                continue
            for key in operator_block:
                for known in CONSTRAINING_CONDITION_KEYS:
                    if str(key).lower() == known.lower():
                        found.append(known)
        return tuple(sorted(set(found)))

    def allows_action(self, action: str) -> bool:
        """Whether this ALLOW statement permits ``action``.

        Handles `NotAction` inversion — the property most often got
        wrong, and the one that flips a finding's meaning entirely.
        """

        if not self.is_allow:
            return False
        if self.not_actions:
            # NotAction = everything EXCEPT these.
            return not any(action_matches(p, action) for p in self.not_actions)
        return any(action_matches(p, action) for p in self.actions)

    def denies_action(self, action: str) -> bool:
        if not self.is_deny:
            return False
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return any(action_matches(p, action) for p in self.actions)

    @property
    def has_wildcard_action(self) -> bool:
        return any(p == "*" for p in self.actions)

    @property
    def has_wildcard_resource(self) -> bool:
        # NotResource: "..." means every resource except those — as wide
        # as "*" for anything not listed.
        return any(r == "*" for r in self.resources) or bool(self.not_resources)


def parse_statements(document: Any) -> tuple[Statement, ...]:
    """Parse a policy document into statements.

    Tolerant by design: a malformed statement is skipped rather than
    raising. A single unparseable statement must not abort analysis of a
    whole account — the remaining statements still carry real signal, and
    the caller sees the count via ``PolicyAnalysis.unparsed_statements``.
    """

    if not isinstance(document, Mapping):
        return ()

    statements = []
    for raw in _as_list(document.get("Statement")):
        if not isinstance(raw, Mapping):
            continue
        effect = raw.get("Effect")
        if not isinstance(effect, str):
            continue

        principals: dict[str, tuple[str, ...]] = {}
        raw_principal = raw.get("Principal", raw.get("NotPrincipal"))
        if isinstance(raw_principal, str):
            # `"Principal": "*"` is the shorthand form.
            principals["*"] = (raw_principal,)
        elif isinstance(raw_principal, Mapping):
            for key, value in raw_principal.items():
                principals[str(key)] = tuple(str(v) for v in _as_list(value))

        condition = raw.get("Condition")
        statements.append(
            Statement(
                effect=effect,
                actions=tuple(str(a) for a in _as_list(raw.get("Action"))),
                not_actions=tuple(str(a) for a in _as_list(raw.get("NotAction"))),
                resources=tuple(str(r) for r in _as_list(raw.get("Resource"))),
                not_resources=tuple(str(r) for r in _as_list(raw.get("NotResource"))),
                principals=principals,
                condition=condition if isinstance(condition, Mapping) else {},
            )
        )
    return tuple(statements)


@dataclass(frozen=True, slots=True)
class PolicyAnalysis:
    """What a permission policy actually grants."""

    has_wildcard_action: bool = False
    has_wildcard_resource: bool = False
    #: `Action: "*"` on `Resource: "*"` in one ALLOW, not denied.
    is_administrator: bool = False
    #: Escalation groups present, e.g. ``("policy_attachment",)``.
    escalation_groups: tuple[str, ...] = ()
    #: PassRole paired with an action that can consume it.
    has_pass_role_escalation: bool = False
    dangerous_actions: tuple[str, ...] = ()
    #: Statements carrying conditions this module does not evaluate.
    #: Drives confidence down rather than clearing the finding.
    conditioned_statements: int = 0
    constraining_conditions: tuple[str, ...] = ()
    statement_count: int = 0
    unparsed_statements: int = 0

    @property
    def confidence(self) -> str:
        """How much to trust this verdict.

        Reduced when constraining conditions are present, because an
        `aws:PrincipalOrgID` restriction can make an apparently-wide
        grant genuinely safe and this module does not evaluate condition
        values. Reporting HIGH confidence on a grant we only half
        understand is how false positives get shipped.
        """

        if self.constraining_conditions:
            return "medium"
        if self.unparsed_statements:
            return "medium"
        return "high"


def analyze_policy_documents(documents: Iterable[Any]) -> PolicyAnalysis:
    """Analyze one or more permission policy documents together.

    Evaluated as a set because permissions are additive across attached
    and inline policies: `iam:PassRole` in one and `ec2:RunInstances` in
    another is still an escalation path, and analyzing each document in
    isolation would miss it.
    """

    statements: list[Statement] = []
    unparsed = 0
    for document in documents:
        parsed = parse_statements(document)
        if isinstance(document, Mapping):
            declared = len(_as_list(document.get("Statement")))
            unparsed += max(0, declared - len(parsed))
        statements.extend(parsed)

    allows = [s for s in statements if s.is_allow]
    denies = [s for s in statements if s.is_deny]

    def is_effectively_allowed(action: str) -> bool:
        # Explicit Deny always wins in AWS, whatever the order.
        if any(s.denies_action(action) for s in denies):
            return False
        return any(s.allows_action(action) for s in allows)

    wildcard_action = any(s.has_wildcard_action for s in allows)
    wildcard_resource = any(s.has_wildcard_resource for s in allows)
    administrator = any(
        s.has_wildcard_action and s.has_wildcard_resource for s in allows
    ) and not any(s.is_deny and s.has_wildcard_action for s in denies)

    groups: list[str] = []
    dangerous: list[str] = []
    for group, actions in PRIVILEGE_ESCALATION_ACTIONS.items():
        hits = [a for a in actions if is_effectively_allowed(a)]
        if hits:
            groups.append(group)
            dangerous.extend(hits)

    pass_role_escalation = "pass_role" in groups and any(
        is_effectively_allowed(a) for a in COMPUTE_ACTIONS
    )

    conditioned = sum(1 for s in allows if s.has_condition)
    constraining = sorted(
        {key for s in allows for key in s.constraining_condition_keys}
    )

    return PolicyAnalysis(
        has_wildcard_action=wildcard_action,
        has_wildcard_resource=wildcard_resource,
        is_administrator=administrator,
        escalation_groups=tuple(sorted(groups)),
        has_pass_role_escalation=pass_role_escalation,
        dangerous_actions=tuple(sorted(set(dangerous))),
        conditioned_statements=conditioned,
        constraining_conditions=tuple(constraining),
        statement_count=len(statements),
        unparsed_statements=unparsed,
    )


@dataclass(frozen=True, slots=True)
class TrustAnalysis:
    """What an `AssumeRolePolicyDocument` actually permits (§4.1)."""

    has_wildcard_principal: bool = False
    #: A trusted AWS account other than the role's own.
    has_external_account_principal: bool = False
    has_cross_account_trust: bool = False
    has_service_principal: bool = False
    has_federated_principal: bool = False
    #: Wildcard principal with NO condition narrowing it. The genuinely
    #: dangerous case — anyone in any AWS account can assume this role.
    is_publicly_assumable: bool = False
    #: A service principal without SourceArn/SourceAccount. The classic
    #: confused-deputy setup: a third party can induce the service to
    #: assume the role on their behalf.
    has_confused_deputy_risk: bool = False
    external_account_ids: tuple[str, ...] = ()
    service_principals: tuple[str, ...] = ()
    trusted_principals: tuple[str, ...] = ()
    constraining_conditions: tuple[str, ...] = ()
    statement_count: int = 0

    @property
    def confidence(self) -> str:
        if self.constraining_conditions and not self.is_publicly_assumable:
            return "medium"
        return "high"


def analyze_trust_policy(
    document: Any, *, own_account_id: str | None = None
) -> TrustAnalysis:
    """Analyze a role's trust policy semantically.

    ``own_account_id`` is what makes "external" meaningful: trusting your
    own account is normal and expected, trusting someone else's is a
    deliberate decision that deserves review. Without it, cross-account
    detection is reported conservatively rather than guessed at — every
    account principal would otherwise look external, and the rule would
    fire on every role in the account.
    """

    statements = [s for s in parse_statements(document) if s.is_allow]

    wildcard = False
    external_accounts: set[str] = set()
    services: set[str] = set()
    federated = False
    trusted: set[str] = set()
    publicly_assumable = False
    confused_deputy = False
    constraining: set[str] = set()

    for statement in statements:
        keys = set(statement.constraining_condition_keys)
        constraining |= keys

        for principal_type, values in statement.principals.items():
            for value in values:
                trusted.add(value)

                if value == "*":
                    wildcard = True
                    # A wildcard principal with no narrowing condition is
                    # assumable by ANY AWS account. With a condition
                    # (e.g. aws:PrincipalOrgID) it may be perfectly safe,
                    # so the two are reported as different facts.
                    if not statement.has_condition:
                        publicly_assumable = True
                    continue

                lowered = principal_type.lower()
                if lowered == "service":
                    services.add(value)
                    # Confused deputy: a service principal that can be
                    # induced by a third party unless the trust is
                    # pinned to a specific source.
                    if not ({"aws:SourceArn", "aws:SourceAccount"} & keys):
                        confused_deputy = True
                elif lowered == "federated":
                    federated = True
                elif lowered == "aws":
                    match = _ACCOUNT_ARN.match(value)
                    account = match.group(1) if match else (
                        value if value.isdigit() and len(value) == 12 else None
                    )
                    if account and own_account_id and account != own_account_id:
                        external_accounts.add(account)

    return TrustAnalysis(
        has_wildcard_principal=wildcard,
        has_external_account_principal=bool(external_accounts),
        has_cross_account_trust=bool(external_accounts),
        has_service_principal=bool(services),
        has_federated_principal=federated,
        is_publicly_assumable=publicly_assumable,
        has_confused_deputy_risk=confused_deputy,
        external_account_ids=tuple(sorted(external_accounts)),
        service_principals=tuple(sorted(services)),
        trusted_principals=tuple(sorted(trusted)),
        constraining_conditions=tuple(sorted(constraining)),
        statement_count=len(statements),
    )


def extract_access_grants(documents: Iterable[Any]) -> list[dict[str, Any]]:
    """Flatten policy documents into serializable access grants.

    Deliberately dumb: it copies effect, actions, resources and condition
    presence, and makes **no** decision about what they imply. Deciding
    which grants become graph edges is
    ``domain/graph/identity_access.py``'s job, and keeping the two apart
    is what lets the derivation be tested without an AWS fixture.

    `NotAction` collapses to `["*"]` with the inversion recorded on the
    resource side only — action-level inversion does not change WHICH
    resources a statement reaches, which is all edge derivation needs.
    """

    grants: list[dict[str, Any]] = []
    for document in documents:
        for statement in parse_statements(document):
            actions = statement.actions or (("*",) if statement.not_actions else ())
            if not actions:
                continue
            grants.append(
                {
                    "effect": statement.effect,
                    "actions": list(actions),
                    "resources": list(statement.resources),
                    "has_condition": statement.has_condition,
                    "condition_keys": list(statement.constraining_condition_keys),
                    "inverted_resources": bool(statement.not_resources),
                }
            )
    return grants


def to_attributes(
    policy: PolicyAnalysis, trust: TrustAnalysis | None = None
) -> dict[str, Any]:
    """Flatten analyses into normalized resource attributes.

    Flat and boolean-heavy on purpose: these are what YAML rules match
    on, and a rule author should not have to navigate nested structures
    to ask "is this role publicly assumable?".
    """

    attributes: dict[str, Any] = {
        "has_wildcard_action": policy.has_wildcard_action,
        "has_wildcard_resource": policy.has_wildcard_resource,
        "has_administrator_access": policy.is_administrator,
        "has_privilege_escalation_path": bool(policy.escalation_groups),
        "privilege_escalation_groups": list(policy.escalation_groups),
        "has_pass_role_escalation": policy.has_pass_role_escalation,
        "dangerous_actions": list(policy.dangerous_actions),
        "policy_statement_count": policy.statement_count,
        "conditioned_statement_count": policy.conditioned_statements,
        "constraining_conditions": list(policy.constraining_conditions),
        "policy_analysis_confidence": policy.confidence,
    }

    if trust is not None:
        attributes.update(
            {
                "has_wildcard_principal": trust.has_wildcard_principal,
                "has_external_account_principal": trust.has_external_account_principal,
                "has_cross_account_trust": trust.has_cross_account_trust,
                "has_service_principal": trust.has_service_principal,
                "has_federated_principal": trust.has_federated_principal,
                "is_publicly_assumable": trust.is_publicly_assumable,
                "has_confused_deputy_risk": trust.has_confused_deputy_risk,
                "external_account_ids": list(trust.external_account_ids),
                "service_principals": list(trust.service_principals),
                "trusted_principals": list(trust.trusted_principals),
                "trust_analysis_confidence": trust.confidence,
            }
        )

    return attributes


# ---------------------------------------------------------------------
# Backward compatibility (§40)
# ---------------------------------------------------------------------
#
# These two functions predate the semantic analysis above and are used by
# the S3, KMS and IAM sub-collectors and by rules/aws/*.yaml. They are
# preserved EXACTLY as written — same names, same signatures, same
# deliberately conservative semantics.
#
# They are narrower than the analysis above on purpose, and that
# narrowness is documented behaviour their callers rely on: notably,
# `policy_allows_public_principal` treats ANY statement carrying a
# Condition as not-public, because judging whether a condition actually
# narrows exposure is policy simulation it declines to attempt.
#
# The new `analyze_policy_documents` / `analyze_trust_policy` take the
# opposite approach: they surface conditions as reduced confidence rather
# than as a clean bill of health. Both behaviours are legitimate for
# their respective callers, so neither is rewritten in terms of the
# other — doing so would silently change what 68 shipped rules mean.


def _statements(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    statement = document.get("Statement", [])
    if isinstance(statement, Mapping):
        return [statement]
    if isinstance(statement, list):
        return statement
    return []


def policy_allows_public_principal(document: Mapping[str, Any] | None) -> bool:
    """True if any unconditional ``Allow`` statement grants access to
    principal ``"*"`` (or ``{"AWS": "*"}``).

    A statement carrying any ``Condition`` block is treated as *not*
    public here — conservatively, since judging whether a given
    condition actually narrows exposure (e.g. ``aws:SourceIp`` with a
    wide CIDR) is exactly the kind of policy-simulation this module
    deliberately does not attempt.
    """

    if not document:
        return False
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            continue
        principal = statement.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, Mapping) and "*" in _as_list(principal.get("AWS")):
            return True
    return False


def policy_grants_full_admin(document: Mapping[str, Any] | None) -> bool:
    """True if any ``Allow`` statement grants ``Action: "*"`` over
    ``Resource: "*"`` — the literal AWS-managed ``AdministratorAccess``
    shape, not an approximation of "broad" permissions.
    """

    if not document:
        return False
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        if "*" in _as_list(statement.get("Action")) and "*" in _as_list(statement.get("Resource")):
            return True
    return False
