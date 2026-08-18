"""Typed, validated identifiers used throughout the Domain.

Plain ``str`` identifiers would let a ``ResourceId`` be passed where a
``TenantId`` is expected without any error. Each identifier below is a
distinct, immutable value object so such mistakes are caught by
construction and by type checking, not by convention.
"""

from __future__ import annotations

from dataclasses import dataclass

from domain.shared.errors import DomainError


class InvalidIdentifier(DomainError):
    """An identifier value object was constructed from a blank string."""


UNKNOWN_ACCOUNT = "unknown-account"
"""Stand-in used when a resource's owning account could not be determined.

Collectors normally stamp every resource with its AWS account id or Azure
subscription id, but a documented non-fatal case exists: the credential
may lack ``sts:GetCallerIdentity`` (or the Azure equivalent). Rather than
leave the account component of an identity blank — which would make two
different unknown accounts indistinguishable from one *known* account —
identity composition substitutes this explicit sentinel.

It is a single shared constant because several layers must agree on it
byte-for-byte: scan keys, logical finding ids, and lifecycle coverage
matching all compose it, and a divergence between any two of them would
show up as findings that never resolve (or, worse, resolve wrongly).
"""


def account_key(account_id: str | None) -> str:
    """Normalize an optional account id for identity comparison."""

    return account_id or UNKNOWN_ACCOUNT


@dataclass(frozen=True, slots=True)
class _Identifier:
    """Base for all typed identifiers. Not exported directly."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise InvalidIdentifier(
                f"{type(self).__name__} must be a non-blank string, got {self.value!r}"
            )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class TenantId(_Identifier):
    """Identifies a tenant. The root of the isolation invariant."""


@dataclass(frozen=True, slots=True)
class ResourceId(_Identifier):
    """Identifies a normalized resource, unique within its tenant."""


@dataclass(frozen=True, slots=True)
class RuleId(_Identifier):
    """Identifies a compliance rule."""


@dataclass(frozen=True, slots=True)
class FindingId(_Identifier):
    """Identifies a finding."""


@dataclass(frozen=True, slots=True)
class AttackPathId(_Identifier):
    """Identifies an attack path."""
