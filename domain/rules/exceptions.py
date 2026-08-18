"""Accepted-risk exceptions / suppressions (CSPM upgrade §28).

Every enterprise has findings it has consciously decided to accept: a
bucket that is public because it serves a website, a role with broad
trust because it is the CI deployer. Without a first-class way to record
that, one of two things happens, and both are bad:

* the team disables the rule entirely, losing coverage of every OTHER
  resource it protects, or
* the finding is ignored, and real regressions hide in a permanently
  noisy report.

## The rule this module enforces

> **Never silently suppress.** (§28)

A suppressed finding is not deleted and not hidden. It changes state to
SUPPRESSED, keeps its evidence, and carries who approved it, why, and
when the approval lapses. The distinction matters at audit time: "we did
not detect this" and "we detected it and accepted it in writing" are
completely different answers to a regulator.

## Expiry is mandatory-by-default, not optional

An exception with no end date is a permanently disabled control that
nobody will ever revisit — the same outcome as deleting the rule, but
harder to notice. ``expires_at`` is therefore required unless a caller
explicitly constructs a permanent exception, which is a deliberate,
visible act.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from domain.shared.errors import DomainError
from domain.shared.identifiers import RuleId, TenantId
from domain.shared.temporal import is_timezone_aware


class InvalidException(DomainError):
    """An exception record was constructed with incoherent data."""


class ExceptionScope(str, Enum):
    """What an exception covers.

    Ordered from narrowest to widest. Narrower is safer: a RESOURCE
    exception waives one finding, an ACCOUNT exception waives a control
    across everything in that account, which is close to disabling it.
    """

    RESOURCE = "resource"
    ACCOUNT = "account"
    TENANT = "tenant"


@dataclass(frozen=True, slots=True)
class RuleException:
    """One approved, time-bounded, justified waiver.

    Deliberately carries no "suppress everything" mode: the widest scope
    is TENANT for a single rule. There is no way to express "suppress all
    rules", because that is not risk acceptance, it is turning the
    product off.
    """

    rule_id: RuleId
    tenant_id: TenantId
    scope: ExceptionScope
    #: The resource id or account id this applies to. ``None`` only for
    #: TENANT scope, where the tenant is already identified.
    scope_value: str | None
    #: Why this risk is accepted. Free text, but required and non-blank:
    #: an unjustified waiver is indistinguishable from an oversight when
    #: someone reviews it a year later.
    justification: str
    #: Who accepted the risk. Required — accountability is the point.
    approved_by: str
    approved_at: datetime
    #: When the waiver lapses. ``None`` means permanent, which must be a
    #: deliberate choice (see ``permanent()``).
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, RuleId):
            raise InvalidException("rule_id must be a RuleId")
        if not isinstance(self.tenant_id, TenantId):
            raise InvalidException("tenant_id must be a TenantId")
        if not isinstance(self.scope, ExceptionScope):
            raise InvalidException("scope must be an ExceptionScope")

        for name in ("justification", "approved_by"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise InvalidException(
                    f"{name} must be a non-blank string — an unjustified or unattributed "
                    "exception cannot be reviewed later"
                )

        if self.scope is ExceptionScope.TENANT:
            if self.scope_value is not None:
                raise InvalidException(
                    "TENANT scope must not carry a scope_value (the tenant is already identified)"
                )
        elif not isinstance(self.scope_value, str) or not self.scope_value.strip():
            raise InvalidException(f"{self.scope.value} scope requires a non-blank scope_value")

        for name in ("approved_at", "expires_at"):
            value = getattr(self, name)
            if value is None:
                continue
            if not isinstance(value, datetime) or not is_timezone_aware(value):
                raise InvalidException(f"{name} must be a timezone-aware datetime")

        if self.expires_at is not None and self.expires_at <= self.approved_at:
            raise InvalidException("expires_at must be later than approved_at")

    @classmethod
    def permanent(
        cls,
        *,
        rule_id: RuleId,
        tenant_id: TenantId,
        scope: ExceptionScope,
        scope_value: str | None,
        justification: str,
        approved_by: str,
        approved_at: datetime,
    ) -> "RuleException":
        """Construct a never-expiring exception.

        A separate constructor rather than ``expires_at=None`` by
        default, so that creating a permanently disabled control is an
        explicit act that shows up in review — not something achieved by
        omitting an argument.
        """

        return cls(
            rule_id=rule_id,
            tenant_id=tenant_id,
            scope=scope,
            scope_value=scope_value,
            justification=justification,
            approved_by=approved_by,
            approved_at=approved_at,
            expires_at=None,
        )

    def is_active(self, *, at: datetime) -> bool:
        """Whether this waiver applies at ``at``.

        ``at`` is passed in, never read from a clock, keeping the domain
        deterministic — the same rule Phases 1–5 follow.
        """

        if not is_timezone_aware(at):
            raise InvalidException("`at` must be a timezone-aware datetime")
        if at < self.approved_at:
            return False
        return self.expires_at is None or at < self.expires_at

    def covers(
        self, *, rule_id: RuleId, tenant_id: TenantId, resource_id: str, account_id: str | None
    ) -> bool:
        """Whether this waiver matches a specific finding.

        Tenant is checked first and always: an exception approved in one
        tenant must never suppress another tenant's finding, which would
        be a cross-tenant security failure wearing a governance costume.
        """

        if self.tenant_id != tenant_id or self.rule_id != rule_id:
            return False
        if self.scope is ExceptionScope.TENANT:
            return True
        if self.scope is ExceptionScope.ACCOUNT:
            return account_id is not None and self.scope_value == account_id
        return self.scope_value == resource_id


@dataclass(frozen=True, slots=True)
class ExceptionRegistry:
    """The set of waivers in force for a tenant.

    A value object rather than a service: matching is a pure function of
    the exceptions and the finding, so it is trivially testable and has
    no I/O.
    """

    exceptions: tuple[RuleException, ...] = ()

    def find_match(
        self,
        *,
        rule_id: RuleId,
        tenant_id: TenantId,
        resource_id: str,
        account_id: str | None,
        at: datetime,
    ) -> RuleException | None:
        """The active waiver covering this finding, if any.

        Returns the exception itself rather than a bool so the caller can
        record WHICH waiver applied, who approved it and when it lapses.
        A suppressed finding that cannot say why it was suppressed is
        exactly the silent suppression §28 forbids.

        Narrowest scope wins when several match, so a specific
        resource-level justification is preferred over a blanket
        tenant-level one in the audit record.
        """

        matches = [
            exception
            for exception in self.exceptions
            if exception.covers(
                rule_id=rule_id,
                tenant_id=tenant_id,
                resource_id=resource_id,
                account_id=account_id,
            )
            and exception.is_active(at=at)
        ]
        if not matches:
            return None

        precedence = {
            ExceptionScope.RESOURCE: 0,
            ExceptionScope.ACCOUNT: 1,
            ExceptionScope.TENANT: 2,
        }
        return min(matches, key=lambda e: precedence[e.scope])

    def active_at(self, at: datetime) -> tuple[RuleException, ...]:
        return tuple(e for e in self.exceptions if e.is_active(at=at))

    def expired_at(self, at: datetime) -> tuple[RuleException, ...]:
        """Waivers that have lapsed.

        Worth surfacing: a lapsed exception means a control just came
        back into force, and the findings it was hiding are about to
        reappear. Teams should hear about that before the report changes
        under them.
        """

        return tuple(
            e
            for e in self.exceptions
            if e.expires_at is not None and at >= e.expires_at
        )
