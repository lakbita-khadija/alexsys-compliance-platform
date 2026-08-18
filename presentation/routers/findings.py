"""``/api/v1/findings`` (Phase 5, §5, §15).

The endpoint the AI Service depends on most, so its contract is
documented in the decorators rather than only in prose — the OpenAPI
document is the artifact the AI engineer generates a client from (§21),
and a parameter described only in a markdown file does not reach them.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Request, status

from application.findings.query_finding_pages import GetFinding, QueryFindingsPage
from contracts.ai_service.translation import finding_to_contract
from contracts.errors import ContractTranslationError
from presentation.dependencies import CurrentIdentity, FindingFilters, PageParams, SortParam
from presentation.errors import not_found
from presentation.schemas import (
    AiFindingContract,
    ErrorEnvelope,
    FindingResource,
    PageResponse,
)

router = APIRouter(prefix="/findings", tags=["findings"])

_ERROR_RESPONSES: dict[int | str, dict] = {
    401: {"model": ErrorEnvelope, "description": "Missing, malformed, expired or badly signed token."},
    403: {"model": ErrorEnvelope, "description": "Authenticated, but lacking the 'reader' role."},
    422: {"model": ErrorEnvelope, "description": "Invalid filter, enum value, or pagination bound."},
}


def _use_cases(request: Request) -> tuple[QueryFindingsPage, GetFinding]:
    return request.app.state.query_findings, request.app.state.get_finding


@router.get(
    "",
    response_model=PageResponse[FindingResource],
    responses=_ERROR_RESPONSES,
    summary="List findings",
    description=(
        "One page of findings for the **authenticated tenant**.\n\n"
        "The tenant is taken from the verified JWT. There is no `tenant_id` "
        "parameter, and supplying one has no effect on scoping.\n\n"
        "`status=indeterminate` findings are returned like any other and must "
        "not be treated as passes — they mean the check could not be evaluated."
    ),
)
def list_findings(
    request: Request,
    identity: CurrentIdentity,
    filters: FindingFilters,
    page: PageParams,
    sort: SortParam,
) -> PageResponse:
    query, _ = _use_cases(request)
    result = query.execute(identity=identity, filters=filters, page=page, sort=sort)
    return PageResponse.of(result, [FindingResource.of(f) for f in result.items])


# Declared BEFORE `/{finding_id}` so the literal path wins the match —
# otherwise "ai-contract" would be captured as a finding id.
#
# A separate path rather than a `?view=ai` parameter: a query parameter
# that changes the RESPONSE SCHEMA makes the OpenAPI document ambiguous,
# and a client generated from it gets one type for two shapes. Two paths,
# two response models, one generated client per shape.
@router.get(
    "/ai-contract",
    response_model=PageResponse[AiFindingContract],
    responses=_ERROR_RESPONSES,
    summary="List findings in the frozen AI contract shape",
    description=(
        "Identical filtering and pagination to `GET /findings`, but each item is the "
        "exact 11-field payload `contracts/ai_service` specifies.\n\n"
        "**INDETERMINATE findings are omitted** — that contract's status enum has only "
        "`pass` and `fail`, and coercing an unevaluated check into either would be "
        "inventing a verdict. `total` still reflects the unfiltered match count, so "
        "`len(items)` may be smaller than the page size. Use `GET /findings` if you "
        "need to see indeterminate results."
    ),
)
def list_findings_ai_contract(
    request: Request,
    identity: CurrentIdentity,
    filters: FindingFilters,
    page: PageParams,
    sort: SortParam,
) -> PageResponse:
    query, _ = _use_cases(request)
    result = query.execute(identity=identity, filters=filters, page=page, sort=sort)

    items = []
    for finding in result.items:
        try:
            # Projected through the EXISTING ACL, never re-derived here,
            # so the API and every other consumer of the contract cannot
            # drift apart.
            items.append(AiFindingContract(**finding_to_contract(finding).to_payload()))
        except ContractTranslationError:
            continue

    return PageResponse.of(result, items)


@router.get(
    "/{finding_id}",
    response_model=FindingResource,
    responses={
        **_ERROR_RESPONSES,
        404: {
            "model": ErrorEnvelope,
            "description": (
                "No such finding **in this tenant**. Returned identically whether the "
                "finding does not exist or belongs to another tenant, so the response "
                "cannot be used to probe for other tenants' data."
            ),
        },
    },
    summary="Get one finding",
    description=(
        "One finding with its full graph context.\n\n"
        "Unlike the list endpoint this includes `graph_context` — the resource's "
        "neighbourhood at scan time. A resource's edge count is unbounded, so it is "
        "returned here and not in pages.\n\n"
        "`related_attack_path_ids` names the attack paths this resource lies on; "
        "resolve them through `/api/v1/attack-paths/{id}`."
    ),
)
def get_finding(
    request: Request,
    identity: CurrentIdentity,
    finding_id: Annotated[str, Path(description="Physical finding id (per-scan).")],
) -> FindingResource:
    _, get = _use_cases(request)
    finding = get.execute(identity=identity, finding_id=finding_id)
    if finding is None:
        raise not_found("finding")
    # The one place graph context is served: see the field's own note on
    # why a page must not carry it.
    return FindingResource.of(finding, include_graph_context=True)


@router.get(
    "/{finding_id}/ai-contract",
    response_model=AiFindingContract,
    responses={
        **_ERROR_RESPONSES,
        404: {"model": ErrorEnvelope, "description": "No such finding in this tenant."},
        status.HTTP_409_CONFLICT: {
            "model": ErrorEnvelope,
            "description": (
                "The finding cannot be represented in the AI contract — it is "
                "INDETERMINATE, or its framework/domain is outside the contract's "
                "closed vocabulary."
            ),
        },
    },
    summary="Get one finding in the frozen AI contract shape",
    description=(
        "The exact 11-field payload `contracts/ai_service` specifies. Provided so the "
        "AI Service can consume a byte-stable shape independent of additive changes to "
        "the richer API schema."
    ),
)
def get_finding_ai_contract(
    request: Request,
    identity: CurrentIdentity,
    finding_id: Annotated[str, Path()],
) -> AiFindingContract:
    from presentation.errors import ApiError, ErrorCode  # local: avoids a cycle

    _, get = _use_cases(request)
    finding = get.execute(identity=identity, finding_id=finding_id)
    if finding is None:
        raise not_found("finding")
    try:
        return AiFindingContract(**finding_to_contract(finding).to_payload())
    except ContractTranslationError as exc:
        raise ApiError(
            code=ErrorCode.VALIDATION_ERROR,
            message=str(exc),
            status_code=status.HTTP_409_CONFLICT,
        ) from exc
