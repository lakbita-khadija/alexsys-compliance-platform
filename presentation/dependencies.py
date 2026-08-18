"""Request-scoped dependencies (Phase 5, §12, §13, §16, §19).

FastAPI dependencies are where the security boundary is actually
enforced, so this module is short and deliberately boring. Three things
happen here and nothing else:

1. A bearer token is extracted and verified, producing an
   ``AuthenticatedIdentity``. There is no other way for a router to
   obtain one.
2. Pagination parameters are validated and bounded.
3. Filters are parsed from typed query parameters into the application
   layer's closed ``FindingFilter`` / ``ScoreFilter`` vocabulary.

Routers never see the raw ``Authorization`` header, never see a
``tenant_id`` query parameter (there is none), and never build a filter
from arbitrary input.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Callable

from fastapi import Depends, Header, Query, Request

from application.ports.auth import (
    AuthenticatedIdentity,
    AuthenticationError,
    Role,
    TokenVerifier,
)
from application.ports.queries import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    FindingFilter,
    PageRequest,
    ScoreFilter,
    SortOrder,
)
from domain.compliance.scoring import ScoreScope
from domain.findings.models import FindingStatus
from domain.scans.lifecycle import LifecycleState
from domain.shared.enums import CloudProvider, Severity


def get_token_verifier(request: Request) -> TokenVerifier:
    """Pull the verifier off application state.

    Set once at composition (``composition.py``). Reading it from state
    rather than importing a module-level singleton is what lets a test
    build an app with its own key pair without any global mutation.
    """

    verifier = getattr(request.app.state, "token_verifier", None)
    if verifier is None:  # pragma: no cover - a wiring bug, not a runtime path
        raise RuntimeError(
            "no TokenVerifier configured on app.state; the app was not built by composition.py"
        )
    return verifier


def current_identity(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> AuthenticatedIdentity:
    """Authenticate the caller (§13).

    Every failure path raises ``AuthenticationError``, which the error
    handler renders as a generic 401 — the specific reason goes to the
    log only.
    """

    if not authorization:
        raise AuthenticationError("missing Authorization header")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationError("Authorization header must be 'Bearer <token>'")

    identity = get_token_verifier(request).verify(token.strip())

    # Stashed for the audit recorder and the access log. Note what is
    # stored: the SUBJECT and TENANT, never the token itself.
    request.state.identity = identity
    return identity


CurrentIdentity = Annotated[AuthenticatedIdentity, Depends(current_identity)]


def require_role(role: Role) -> Callable[[AuthenticatedIdentity], AuthenticatedIdentity]:
    """Build a dependency that enforces one role.

    Used as a route dependency so the requirement is visible in the
    route definition — and therefore in the generated OpenAPI — rather
    than buried in a handler body.
    """

    def _dependency(identity: CurrentIdentity) -> AuthenticatedIdentity:
        identity.require_role(role)
        return identity

    return _dependency


def page_request(
    limit: Annotated[
        int,
        Query(
            ge=1,
            le=MAX_LIMIT,
            description=f"Page size. Default {DEFAULT_LIMIT}, maximum {MAX_LIMIT}.",
        ),
    ] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, description="Zero-based offset.")] = 0,
) -> PageRequest:
    """Bounded pagination (§19).

    The bounds are declared twice on purpose: FastAPI's ``ge``/``le``
    produce a clean 422 with a helpful message, and ``PageRequest``
    re-validates because it is also constructed from non-HTTP callers
    (the job runner, tests) that never pass through this dependency.
    """

    return PageRequest(limit=limit, offset=offset)


PageParams = Annotated[PageRequest, Depends(page_request)]


def finding_filters(
    framework: Annotated[str | None, Query(description="Framework id, e.g. iso_27001.")] = None,
    severity: Annotated[Severity | None, Query(description="critical | high | medium | low")] = None,
    status: Annotated[
        FindingStatus | None,
        Query(description="fail | pass | indeterminate. 'indeterminate' is NOT a pass."),
    ] = None,
    lifecycle_state: Annotated[
        LifecycleState | None, Query(description="open | resolved | reopened | suppressed")
    ] = None,
    domain: Annotated[str | None, Query(description="Risk domain, e.g. storage.")] = None,
    provider: Annotated[CloudProvider | None, Query(description="aws | azure")] = None,
    resource_id: Annotated[str | None, Query()] = None,
    rule_id: Annotated[str | None, Query()] = None,
    scan_key: Annotated[str | None, Query(description="Restrict to one scan.")] = None,
    account_id: Annotated[str | None, Query()] = None,
    detected_after: Annotated[datetime | None, Query()] = None,
    detected_before: Annotated[datetime | None, Query()] = None,
) -> FindingFilter:
    """Typed finding filters (§19).

    Every enum-valued parameter is declared as its enum, so FastAPI
    rejects an unknown value with a 422 listing the permitted ones
    before any application code runs. There is no free-form filter
    parameter, and no path by which caller input becomes part of a query
    structure.

    ``tenant_id`` is conspicuously absent: it is the security boundary,
    taken from the verified token, not a filter.
    """

    return FindingFilter(
        framework=framework,
        severity=severity,
        status=status,
        lifecycle_state=lifecycle_state,
        domain=domain,
        provider=provider,
        resource_id=resource_id,
        rule_id=rule_id,
        scan_key=scan_key,
        account_id=account_id,
        detected_after=detected_after,
        detected_before=detected_before,
    )


FindingFilters = Annotated[FindingFilter, Depends(finding_filters)]


def sort_order(
    sort: Annotated[
        SortOrder,
        Query(description="Deterministic orderings only; each has a unique tiebreaker."),
    ] = SortOrder.DETECTED_AT_DESC,
) -> SortOrder:
    return sort


SortParam = Annotated[SortOrder, Depends(sort_order)]


def score_filters(
    scope: Annotated[
        ScoreScope | None, Query(description="tenant | framework | domain | scan")
    ] = None,
    scope_value: Annotated[
        str | None, Query(description="The framework id / domain name / scan key. Requires scope.")
    ] = None,
    scan_key: Annotated[str | None, Query()] = None,
    computed_after: Annotated[datetime | None, Query()] = None,
    computed_before: Annotated[datetime | None, Query()] = None,
) -> ScoreFilter:
    return ScoreFilter(
        scope=scope,
        scope_value=scope_value,
        scan_key=scan_key,
        computed_after=computed_after,
        computed_before=computed_before,
    )


ScoreFilters = Annotated[ScoreFilter, Depends(score_filters)]
