"""Unauthenticated operational endpoints: health, version, JWKS.

These are the only routes without authentication, and each has a reason:

* ``/health`` — a load balancer cannot present a JWT. It reports
  liveness and database reachability and nothing else; a health endpoint
  that leaks version numbers, table counts or configuration is a
  reconnaissance gift.
* ``/version`` — build identification for support. Deliberately coarse.
* ``/.well-known/jwks.json`` — the PUBLIC verification keys. It is meant
  to be world-readable: that is what lets the AI Service verify tokens
  offline instead of calling Core on every request, and what makes key
  rotation possible without redeploying consumers (§13).

They sit outside ``/api/v1`` on purpose. Infrastructure endpoints are
not part of the versioned data contract and should not move when the
API version does.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from presentation.schemas import HealthResponse, VersionResponse

router = APIRouter(tags=["meta"])

SERVICE_NAME = "complianceiq-core"
SERVICE_VERSION = "0.1.0"
API_VERSION = "v1"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness and dependency health",
    description=(
        "Unauthenticated. Returns 200 when the service can serve traffic and 503 when "
        "it cannot reach its database. Reports no version or configuration detail."
    ),
    responses={503: {"model": HealthResponse, "description": "Database unreachable."}},
)
def health(request: Request, response: Response) -> HealthResponse:
    check = getattr(request.app.state, "health_check", None)

    database_ok = True
    if check is not None:
        try:
            database_ok = bool(check())
        except Exception:  # noqa: BLE001 - any failure means "unhealthy"
            # Swallowed deliberately: the REASON belongs in logs, not in
            # an unauthenticated response that anyone can poll.
            database_ok = False

    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthResponse(status="degraded", database="unavailable")
    return HealthResponse(status="ok", database="ok")


@router.get("/version", response_model=VersionResponse, summary="Service and API version")
def version() -> VersionResponse:
    return VersionResponse(
        service=SERVICE_NAME, version=SERVICE_VERSION, api_version=API_VERSION
    )


@router.get(
    "/.well-known/jwks.json",
    summary="Public JWT verification keys (JWKS)",
    description=(
        "Unauthenticated and intended to be public. Contains only PUBLIC key material "
        "(RSA modulus and exponent) — never a private key.\n\n"
        "The AI Service should fetch and cache this to verify tokens locally rather "
        "than calling Core per request."
    ),
)
def jwks(request: Request) -> dict:
    issuer = getattr(request.app.state, "token_issuer", None)
    if issuer is None:
        # A verify-only deployment holds no signing key and therefore
        # publishes no JWKS. An empty key set is the correct, spec-valid
        # answer — not an error.
        return {"keys": []}
    return dict(issuer.public_jwks())
