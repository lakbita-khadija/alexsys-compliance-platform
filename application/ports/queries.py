"""Paged, filtered read ports for the API (Phase 5, §6, §19, §24).

Phase 4's repositories answer "everything for this scan". The API needs
something different: "page 3 of this tenant's high-severity open
findings in the storage domain, newest first". That is a different
access pattern, so it gets its own ports rather than being bolted onto
the write-side repositories.

Three rules are enforced by the *types* here, not by discipline:

**Pagination is not optional.** Every list method takes a ``PageRequest``
whose limit is bounded at construction. There is no way to call these
ports in a way that returns an unbounded result set, so the classic
"someone added an endpoint that selects the whole table" failure cannot
happen through this interface.

**Filters are a closed, typed vocabulary.** ``FindingFilter`` has named
optional fields — not a dict, not a query string, not a SQL fragment.
An unknown filter is rejected before it reaches the database, and there
is no code path where caller input becomes part of a query structure.

**Tenant is mandatory on every method.** Same rule as Phase 4: a method
that cannot be called without naming a tenant cannot accidentally return
another tenant's rows.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Generic, Sequence, TypeVar

from domain.audit.models import AuditEvent
from domain.compliance.scoring import ComplianceScore, ScoreScope
from domain.findings.models import Finding, FindingStatus
from domain.scans.lifecycle import LifecycleState
from domain.shared.enums import CloudProvider, Severity
from domain.shared.identifiers import TenantId

T = TypeVar("T")


class InvalidQuery(Exception):
    """A query was constructed with parameters outside the contract.

    Raised at construction, in the application layer, so a bad request
    is rejected before any database work happens. Maps to HTTP 422.
    """


#: The API's paging bounds (§19). ``MAX_LIMIT`` is the important one:
#: it is the difference between a slow endpoint and one a single client
#: can use to exhaust the server's memory.
DEFAULT_LIMIT = 50
MAX_LIMIT = 100


@dataclass(frozen=True, slots=True)
class PageRequest:
    """A bounded window over a result set.

    Offset paging, deliberately, matching §6's ``{items,total,limit,
    offset}`` contract. Its known weakness — a row inserted during
    traversal can shift later pages — is mitigated by mandatory
    deterministic ordering (see ``SortOrder``), and cursor paging can be
    added later as an additive alternative without breaking this shape.
    """

    limit: int = DEFAULT_LIMIT
    offset: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.limit, int) or isinstance(self.limit, bool):
            raise InvalidQuery("limit must be an integer")
        if not isinstance(self.offset, int) or isinstance(self.offset, bool):
            raise InvalidQuery("offset must be an integer")
        if self.limit < 1:
            raise InvalidQuery("limit must be at least 1")
        if self.limit > MAX_LIMIT:
            raise InvalidQuery(f"limit must not exceed {MAX_LIMIT}, got {self.limit}")
        if self.offset < 0:
            raise InvalidQuery("offset must not be negative")


@dataclass(frozen=True, slots=True)
class Page(Generic[T]):
    """One page of results plus the total matching count.

    ``total`` is the count of everything matching the filter, not the
    length of ``items`` — that is what lets a client render "showing
    51-100 of 1,284" and compute how many pages exist.
    """

    items: tuple[T, ...]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class SortOrder(str, Enum):
    """Allowed sort orders for findings.

    A closed enum rather than a free "sort by" string: arbitrary sort
    fields are both an injection surface and a performance trap (sorting
    by an unindexed column on a large tenant). Every value here is backed
    by an index.

    Each order ends with a unique tiebreaker (``id``). Without one,
    rows with equal ``detected_at`` can be returned in a different order
    on each query, so a row can appear on two pages or none — the
    classic unstable-pagination bug (§19).
    """

    DETECTED_AT_DESC = "detected_at_desc"
    DETECTED_AT_ASC = "detected_at_asc"
    SEVERITY_DESC = "severity_desc"


@dataclass(frozen=True, slots=True)
class FindingFilter:
    """Typed filters for ``GET /api/v1/findings`` (§5, §19).

    Note what is absent: ``tenant_id``. It is not a filter, it is the
    security boundary, and it is supplied separately from the verified
    token. Putting it here would make it look like just another optional
    predicate a caller could set — which is exactly the mistake §12
    warns about.
    """

    framework: str | None = None
    severity: Severity | None = None
    status: FindingStatus | None = None
    lifecycle_state: LifecycleState | None = None
    domain: str | None = None
    provider: CloudProvider | None = None
    resource_id: str | None = None
    rule_id: str | None = None
    scan_key: str | None = None
    account_id: str | None = None
    detected_after: datetime | None = None
    detected_before: datetime | None = None

    def __post_init__(self) -> None:
        if (
            self.detected_after is not None
            and self.detected_before is not None
            and self.detected_after > self.detected_before
        ):
            raise InvalidQuery("detected_after must not be later than detected_before")


@dataclass(frozen=True, slots=True)
class ScoreFilter:
    """Typed filters for ``GET /api/v1/scores`` (§5)."""

    scope: ScoreScope | None = None
    scope_value: str | None = None
    scan_key: str | None = None
    computed_after: datetime | None = None
    computed_before: datetime | None = None

    def __post_init__(self) -> None:
        if (
            self.computed_after is not None
            and self.computed_before is not None
            and self.computed_after > self.computed_before
        ):
            raise InvalidQuery("computed_after must not be later than computed_before")
        if self.scope_value is not None and self.scope is None:
            # A scope_value without a scope is ambiguous: "iso_27001"
            # could be a framework or (in principle) a domain name.
            raise InvalidQuery("scope_value requires scope to be specified")


class FindingQueryRepository(ABC):
    """Port: paged, filtered, tenant-scoped reads over findings."""

    @abstractmethod
    def search(
        self,
        *,
        tenant_id: TenantId,
        filters: FindingFilter,
        page: PageRequest,
        sort: SortOrder = SortOrder.DETECTED_AT_DESC,
    ) -> Page[Finding]:
        """One page of findings matching ``filters``, plus the total.

        Implementations MUST paginate and count in the database. Loading
        every match and slicing in Python satisfies the signature and
        defeats its purpose (§34).
        """

    @abstractmethod
    def get(self, *, tenant_id: TenantId, finding_id: str) -> Finding | None:
        """One finding, or ``None`` if it does not exist **within this
        tenant**.

        The two cases are deliberately indistinguishable to the caller:
        "no such finding" and "exists, but belongs to another tenant"
        both return ``None``, so the API can answer 404 for both and a
        caller cannot probe for the existence of another tenant's data
        (§12).
        """


class ComplianceScoreRepository(ABC):
    """Port: persisted compliance scores (§11)."""

    @abstractmethod
    def save_all(self, *, tenant_id: TenantId, scores: Sequence[ComplianceScore]) -> int:
        """Persist scores, replacing any with the same identity."""

    @abstractmethod
    def search(
        self, *, tenant_id: TenantId, filters: ScoreFilter, page: PageRequest
    ) -> Page[ComplianceScore]:
        """One page of scores, newest first, with a stable tiebreaker."""

    @abstractmethod
    def latest(
        self, *, tenant_id: TenantId, scope: ScoreScope, scope_value: str | None = None
    ) -> ComplianceScore | None:
        """The most recent score for one scope — "what is our compliance
        posture right now?", the dashboard's headline number.
        """


class AuditEventRepository(ABC):
    """Port: the append-only audit trail (§27).

    Exposes ``record`` and reads, and deliberately no update or delete.
    An audit trail with an edit path is not evidence.
    """

    @abstractmethod
    def record(self, event: AuditEvent) -> None:
        """Append one event."""

    @abstractmethod
    def search(
        self, *, tenant_id: TenantId, page: PageRequest
    ) -> Page[AuditEvent]:
        """One page of a tenant's audit events, newest first."""
