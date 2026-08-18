"""``/api/v1/attack-paths`` and ``/api/v1/scans/{id}/attack-paths`` (STEP 5).

Attack paths were computed by every scan and then discarded at the
persistence boundary. STEP 4 stored them; this exposes them.

Two shapes, deliberately:

* **scan-scoped list** — every path from one scan, plus a severity
  summary, in one round trip. The dashboard's landing screen needs both,
  and two endpoints would guarantee they eventually disagree.
* **single path** — the full chain, evidence and scoring breakdown, so a
  responder can see *why* a number is what it is.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Request

from presentation.dependencies import CurrentIdentity
from presentation.errors import not_found
from presentation.schemas import (
    AttackPathListResponse,
    AttackPathResource,
    AttackPathSummary,
    ErrorEnvelope,
)

router = APIRouter(tags=["attack-paths"])

_ERROR_RESPONSES: dict[int | str, dict] = {
    401: {"model": ErrorEnvelope, "description": "Missing, malformed, expired or badly signed token."},
    403: {"model": ErrorEnvelope, "description": "Authenticated, but lacking the 'reader' role."},
    422: {"model": ErrorEnvelope, "description": "Invalid filter or enum value."},
}

_NOT_FOUND = {
    "model": ErrorEnvelope,
    "description": (
        "No such attack path **in this tenant**. Returned identically whether the "
        "path does not exist or belongs to another tenant, so the response cannot "
        "be used to probe for other tenants' data."
    ),
}

SeverityFilter = Annotated[
    str | None,
    Query(
        description="Only paths at this severity.",
        pattern="^(critical|high|medium|low)$",
    ),
]
ScenarioFilter = Annotated[
    str | None, Query(description="Only paths from this analyzer scenario.", max_length=128)
]
ConfidenceFilter = Annotated[
    str | None,
    Query(
        alias="min_confidence",
        description=(
            "Only paths at or above this confidence. `medium` excludes the "
            "low-confidence paths a conditioned IAM grant produces."
        ),
        pattern="^(unknown|low|medium|high)$",
    ),
]


@router.get(
    "/scans/{scan_id}/attack-paths",
    response_model=AttackPathListResponse,
    responses=_ERROR_RESPONSES,
    summary="Attack paths discovered by one scan",
    description=(
        "Every attack path from one scan, **highest risk first**, with a severity "
        "summary alongside.\n\n"
        "The tenant comes from the verified JWT; there is no `tenant_id` parameter. "
        "A scan belonging to another tenant returns an empty list rather than an "
        "error, for the same reason the single-path endpoint returns 404.\n\n"
        "Each path carries its full ordered chain and its `evidence.score_factors` "
        "breakdown — the score is only useful if it can be defended."
    ),
)
def list_attack_paths_for_scan(
    request: Request,
    identity: CurrentIdentity,
    scan_id: Annotated[str, Path(description="The scan key.", max_length=512)],
    severity: SeverityFilter = None,
    scenario: ScenarioFilter = None,
    min_confidence: ConfidenceFilter = None,
) -> AttackPathListResponse:
    query = request.app.state.query_attack_paths_for_scan
    rows = query.execute(
        identity=identity,
        scan_key=scan_id,
        severity=severity,
        scenario=scenario,
        min_confidence=min_confidence,
    )
    return AttackPathListResponse(
        summary=AttackPathSummary.of(rows),
        items=[AttackPathResource.of(r) for r in rows],
    )


@router.get(
    "/attack-paths/{attack_path_id}",
    response_model=AttackPathResource,
    responses={**_ERROR_RESPONSES, 404: _NOT_FOUND},
    summary="One attack path",
    description=(
        "The complete chain, its evidence and its scoring breakdown.\n\n"
        "`nodes` and `edges` are **ordered** — a path whose hops reorder is a "
        "different path.\n\n"
        "`contributing_finding_ids` links back to the findings on resources along "
        "the chain, so a responder can pivot between the composite risk and the "
        "individual misconfigurations that create it."
    ),
)
def get_attack_path(
    request: Request,
    identity: CurrentIdentity,
    attack_path_id: Annotated[str, Path(description="The attack path id.", max_length=1024)],
) -> AttackPathResource:
    row = request.app.state.get_attack_path.execute(
        identity=identity, attack_path_id=attack_path_id
    )
    if row is None:
        raise not_found("attack path")
    return AttackPathResource.of(row)
