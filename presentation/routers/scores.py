"""``/api/v1/scores`` (Phase 5, §5, §11, §23).

Designed so the future dashboard can render its executive overview, its
per-framework and per-domain breakdowns, and its trend chart **without
any endpoint being added** — but without speculative endpoints either
(§23). The mechanism is filtering plus a stable time order:

* current posture      → ``/scores/current?scope=tenant``
* by framework         → ``?scope=framework``
* by domain            → ``?scope=domain``
* evolution over time  → ``?scope=framework&scope_value=iso_27001&computed_after=…``
* scan-to-scan compare → two ``?scan_key=`` queries

That is one list endpoint and one "latest" endpoint, covering every
dashboard requirement §23 lists for scores.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request

from application.compliance.query_scores import GetLatestScore, QueryScores
from domain.compliance.scoring import ScoreScope
from presentation.dependencies import CurrentIdentity, PageParams, ScoreFilters
from presentation.errors import not_found
from presentation.schemas import ComplianceScoreResource, ErrorEnvelope, PageResponse

router = APIRouter(prefix="/scores", tags=["scores"])

_ERROR_RESPONSES: dict[int | str, dict] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid token."},
    403: {"model": ErrorEnvelope, "description": "Lacking the 'reader' role."},
    422: {"model": ErrorEnvelope, "description": "Invalid filter or pagination bound."},
}


@router.get(
    "",
    response_model=PageResponse[ComplianceScoreResource],
    responses=_ERROR_RESPONSES,
    summary="List compliance scores",
    description=(
        "One page of scores for the authenticated tenant, newest first.\n\n"
        "**`score` may be `null`.** That means nothing determinate was evaluated in "
        "that scope. Render it as 'no data' — coercing it to 0 or 100 states "
        "something false about the tenant's posture.\n\n"
        "Pair it with `coverage`: a 100% score computed over 4 of 900 checks is an "
        "absent posture, not a good one."
    ),
)
def list_scores(
    request: Request,
    identity: CurrentIdentity,
    filters: ScoreFilters,
    page: PageParams,
) -> PageResponse:
    use_case: QueryScores = request.app.state.query_scores
    result = use_case.execute(identity=identity, filters=filters, page=page)
    return PageResponse.of(result, [ComplianceScoreResource.of(s) for s in result.items])


@router.get(
    "/current",
    response_model=ComplianceScoreResource,
    responses={
        **_ERROR_RESPONSES,
        404: {
            "model": ErrorEnvelope,
            "description": "No score has been computed for this scope yet (no scan has completed).",
        },
    },
    summary="Get the current score for one scope",
    description="The dashboard's headline number. Defaults to the whole-tenant score.",
)
def current_score(
    request: Request,
    identity: CurrentIdentity,
    scope: Annotated[ScoreScope, Query()] = ScoreScope.TENANT,
    scope_value: Annotated[
        str | None,
        Query(description="Framework id / domain name / scan key. Omit for scope=tenant."),
    ] = None,
) -> ComplianceScoreResource:
    use_case: GetLatestScore = request.app.state.get_latest_score
    score = use_case.execute(identity=identity, scope=scope, scope_value=scope_value)
    if score is None:
        raise not_found("score")
    return ComplianceScoreResource.of(score)
