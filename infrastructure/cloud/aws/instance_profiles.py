"""Resolving an EC2 instance profile to the IAM role it carries.

## Why this module exists

`ec2:DescribeInstances` returns `IamInstanceProfile.Arn` — the ARN of the
**instance profile**, not of the role. Those are different AWS resources:

```
arn:aws:iam::111111111111:instance-profile/AppServerProfile   ← what EC2 gives us
arn:aws:iam::111111111111:role/AppServerRole                  ← what we need
```

A profile is a container that holds a role. The names frequently match,
because most tooling creates them as a pair — and **that is a convention,
not a fact**. Terraform, CDK, the console and hand-rolled scripts all
allow them to differ, and plenty of real estates have
`profile/web` holding `role/ec2-web-prod`.

Deriving one from the other by string manipulation would fabricate a graph
edge: an assertion that this workload can assume that identity, which
nothing observed. In an attack path that becomes a confident CRITICAL
finding about a privilege relationship that may not exist — the exact
class of error the analyzer refuses everywhere else.

So the role is obtained from `iam:GetInstanceProfile`, or not at all.

## What "not at all" means

Six non-resolving outcomes, each distinguishable by callers, because
"there is no profile" and "we were denied" are different facts and a rule
must be able to tell them apart. See :class:`ProfileResolutionStatus`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from infrastructure.cloud.resilience import (
    CollectionStats,
    RetryPolicy,
    call_with_retry,
    error_code_of,
    is_permission_denied,
)

#: `iam:GetInstanceProfile` returns this when the profile named in the
#: instance's own metadata does not exist. Rare but real: a profile can be
#: deleted while instances still reference it.
_NO_SUCH_ENTITY: Final = "NoSuchEntity"

_ARN_PREFIX: Final = "instance-profile/"


class ProfileResolutionStatus:
    """Why an instance profile did or did not resolve to a role.

    A closed vocabulary rather than a bool, because the *reason* changes
    what a reader should do. ``DENIED`` is a scanner permission problem;
    ``NOT_FOUND`` is a customer configuration anomaly; ``CROSS_ACCOUNT``
    is a security signal. Collapsing them into "no edge" would discard
    all of that.
    """

    #: A role ARN was returned by AWS. The only status that emits an edge.
    RESOLVED: Final = "resolved"
    #: The instance carries no instance profile. Not a problem.
    NO_PROFILE: Final = "no_profile"
    #: `iam:GetInstanceProfile` was denied. We do not know the role.
    DENIED: Final = "denied"
    #: AWS says the profile does not exist — a dangling reference.
    NOT_FOUND: Final = "not_found"
    #: The ARN could not be parsed. Never guess at a malformed identifier.
    MALFORMED_ARN: Final = "malformed_arn"
    #: The profile exists and holds no role. Legal in AWS.
    NO_ROLE: Final = "no_role"
    #: The role lives in a different account from the profile. Not
    #: expected from AWS, and not silently linked — see `resolve`.
    CROSS_ACCOUNT: Final = "cross_account"


@dataclass(frozen=True, slots=True)
class InstanceProfileResolution:
    """The outcome of one resolution attempt.

    ``role_arn`` is populated **only** when ``status`` is ``RESOLVED``.
    Every other status carries ``None`` — there is no partial answer, and
    a caller cannot accidentally use a role ARN that was inferred.
    """

    status: str
    role_arn: str | None = None
    role_name: str | None = None
    profile_name: str | None = None
    profile_account_id: str | None = None
    profile_arn: str | None = None

    @property
    def is_resolved(self) -> bool:
        return self.status == ProfileResolutionStatus.RESOLVED and bool(self.role_arn)

    @property
    def is_indeterminate(self) -> bool:
        """Whether we were prevented from learning the answer.

        Distinct from "the answer is no". Only ``DENIED`` qualifies: every
        other non-resolving status is a determinate fact about the estate.
        """

        return self.status == ProfileResolutionStatus.DENIED


def parse_instance_profile_arn(arn: str | None) -> tuple[str, str] | None:
    """``(account_id, profile_name)``, or ``None`` if unparseable.

    Returning ``None`` rather than raising is deliberate: a malformed ARN
    in one instance's metadata must degrade that one instance, not abort
    the collection of every other instance.

    Handles paths — `instance-profile/team/env/Name` has profile name
    `Name`, which is what `iam:GetInstanceProfile` expects.
    """

    if not isinstance(arn, str) or not arn.strip():
        return None

    parts = arn.split(":", 5)
    if len(parts) != 6:
        return None
    if parts[0] != "arn" or parts[2] != "iam":
        return None

    account_id, resource = parts[4], parts[5]
    if not resource.startswith(_ARN_PREFIX):
        return None

    name = resource[len(_ARN_PREFIX) :].rstrip("/").rsplit("/", 1)[-1]
    if not name:
        return None
    return account_id, name


def _account_of(arn: str) -> str | None:
    parts = arn.split(":", 5)
    return parts[4] if len(parts) >= 5 and parts[0] == "arn" else None


def resolve(
    client: Any,
    instance_profile_arn: str | None,
    *,
    own_account_id: str | None = None,
    retry_policy: RetryPolicy | None = None,
    stats: CollectionStats | None = None,
) -> InstanceProfileResolution:
    """Resolve a profile ARN to its role ARN using `iam:GetInstanceProfile`.

    Throttling and transient failures are handled by the shared
    resilience layer — this function deliberately contains **no retry
    logic of its own**, so there is one backoff implementation in the
    codebase rather than one per collector.

    Terminal failures are classified, never propagated as a crash: a
    single unresolvable profile costs one edge, not the scan.
    """

    if not instance_profile_arn:
        return InstanceProfileResolution(status=ProfileResolutionStatus.NO_PROFILE)

    parsed = parse_instance_profile_arn(instance_profile_arn)
    if parsed is None:
        return InstanceProfileResolution(
            status=ProfileResolutionStatus.MALFORMED_ARN,
            profile_arn=instance_profile_arn,
        )
    profile_account_id, profile_name = parsed

    try:
        response = call_with_retry(
            lambda: client.get_instance_profile(InstanceProfileName=profile_name),
            policy=retry_policy,
            stats=stats,
            description="iam:GetInstanceProfile",
        )
    except Exception as exc:  # noqa: BLE001 - classified below, never re-raised
        if is_permission_denied(exc):
            if stats is not None:
                stats.permission_denied += 1
            return InstanceProfileResolution(
                status=ProfileResolutionStatus.DENIED,
                profile_name=profile_name,
                profile_account_id=profile_account_id,
                profile_arn=instance_profile_arn,
            )
        if error_code_of(exc) == _NO_SUCH_ENTITY:
            return InstanceProfileResolution(
                status=ProfileResolutionStatus.NOT_FOUND,
                profile_name=profile_name,
                profile_account_id=profile_account_id,
                profile_arn=instance_profile_arn,
            )
        # Anything else — including a retry budget exhausted by
        # throttling — is treated as "we could not determine it", not as
        # a reason to lose the instance. The stats already record it.
        return InstanceProfileResolution(
            status=ProfileResolutionStatus.DENIED,
            profile_name=profile_name,
            profile_account_id=profile_account_id,
            profile_arn=instance_profile_arn,
        )

    roles = (response or {}).get("InstanceProfile", {}).get("Roles") or []
    role = roles[0] if roles else None
    role_arn = (role or {}).get("Arn")
    if not role_arn or not str(role_arn).strip():
        return InstanceProfileResolution(
            status=ProfileResolutionStatus.NO_ROLE,
            profile_name=profile_name,
            profile_account_id=profile_account_id,
            profile_arn=instance_profile_arn,
        )
    role_arn = str(role_arn)

    # --- Account safety.
    #
    # AWS does not permit an instance profile to hold a role from another
    # account, so a mismatch means either a spoofed response or an
    # assumption of ours that no longer holds. Either way this is not the
    # place to invent cross-account semantics: the edge is withheld and
    # the anomaly is named, so a reader can act on it.
    role_account_id = _account_of(role_arn)
    expected = profile_account_id or own_account_id
    if role_account_id and expected and role_account_id != expected:
        return InstanceProfileResolution(
            status=ProfileResolutionStatus.CROSS_ACCOUNT,
            role_name=(role or {}).get("RoleName"),
            profile_name=profile_name,
            profile_account_id=profile_account_id,
            profile_arn=instance_profile_arn,
        )

    return InstanceProfileResolution(
        status=ProfileResolutionStatus.RESOLVED,
        role_arn=role_arn,
        role_name=(role or {}).get("RoleName"),
        profile_name=profile_name,
        profile_account_id=profile_account_id,
        profile_arn=instance_profile_arn,
    )


__all__ = [
    "InstanceProfileResolution",
    "ProfileResolutionStatus",
    "parse_instance_profile_arn",
    "resolve",
]
