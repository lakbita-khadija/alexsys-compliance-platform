"""``/api/v1/scans`` (Phase 5, §26).

The contract is deliberately job-oriented. ``POST`` returns **202
Accepted** with an id and a status — never findings — because a real
scan takes minutes of throttled cloud API calls and a synchronous
endpoint would time out behind any load balancer. Callers poll
``GET /scans/{scan_key}``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query, Request, status

from application.scanning.submit_scan import GetScan, ListScans, SubmitScan
from domain.scans.models import ScanTarget
from domain.shared.enums import CloudProvider
from presentation.dependencies import CurrentIdentity
from presentation.errors import not_found
from presentation.schemas import (
    ErrorEnvelope,
    ScanRequest,
    ScanResource,
    ScanSubmissionResponse,
)

router = APIRouter(prefix="/scans", tags=["scans"])

_ERROR_RESPONSES: dict[int | str, dict] = {
    401: {"model": ErrorEnvelope, "description": "Missing or invalid token."},
    403: {"model": ErrorEnvelope, "description": "Lacking the required role."},
    422: {"model": ErrorEnvelope, "description": "Invalid request body or parameters."},
}


@router.post(
    "",
    response_model=ScanSubmissionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    responses={
        **_ERROR_RESPONSES,
        403: {
            "model": ErrorEnvelope,
            "description": (
                "Lacking the 'scanner' role. Triggering a scan is separated from "
                "reading data because it spends money and calls real cloud APIs."
            ),
        },
        409: {
            "model": ErrorEnvelope,
            "description": (
                "A scan for this exact target is already queued or running. Scan keys "
                "are deterministic, so a duplicate submission is detected rather than "
                "starting a second concurrent scan of the same account."
            ),
        },
    },
    summary="Trigger a compliance scan",
    description=(
        "**Asynchronous.** Returns `202 Accepted` with a `scan_key` and `status: queued`.\n\n"
        "The scan has NOT run when this returns. Poll `GET /api/v1/scans/{scan_key}` "
        "until `status` is terminal (`completed`, `partial`, `failed`, `cancelled`).\n\n"
        "`partial` means the scan ran but could not enumerate everything — check "
        "`errors`. It is **not** a success: an unreachable service was not verified."
    ),
)
def submit_scan(
    request: Request,
    identity: CurrentIdentity,
    body: ScanRequest,
) -> ScanSubmissionResponse:
    use_case: SubmitScan = request.app.state.submit_scan

    target = ScanTarget(
        provider=CloudProvider(body.provider),
        account_id=body.account_id,
        directory_id=body.directory_id,
        regions=tuple(body.regions),
    )

    submission = use_case.execute(
        identity=identity,
        target=target,
        # Propagated so the whole async pipeline — including the audit
        # events written by the worker minutes later — is traceable back
        # to the request that started it (§16).
        correlation_id=getattr(request.state, "correlation_id", None),
    )

    return ScanSubmissionResponse(
        scan_key=submission.scan_key,
        status=submission.status.value,  # type: ignore[arg-type]
        tenant_id=str(submission.tenant_id),
        submitted_at=submission.submitted_at,
    )


@router.get(
    "",
    response_model=list[ScanResource],
    responses=_ERROR_RESPONSES,
    summary="List recent scans",
)
def list_scans(
    request: Request,
    identity: CurrentIdentity,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ScanResource]:
    use_case: ListScans = request.app.state.list_scans
    scans = use_case.execute(identity=identity, limit=limit, offset=offset)
    return [ScanResource.of(s) for s in scans]


@router.get(
    "/{scan_key}",
    response_model=ScanResource,
    responses={
        **_ERROR_RESPONSES,
        404: {
            "model": ErrorEnvelope,
            "description": (
                "No such scan in this tenant. Identical response whether the scan does "
                "not exist or belongs to another tenant."
            ),
        },
    },
    summary="Get scan status and results summary",
)
def get_scan(
    request: Request,
    identity: CurrentIdentity,
    scan_key: Annotated[str, Path(description="Deterministic scan key from the submission response.")],
) -> ScanResource:
    use_case: GetScan = request.app.state.get_scan
    scan = use_case.execute(identity=identity, scan_key=scan_key)
    if scan is None:
        raise not_found("scan")
    return ScanResource.of(scan)
