"""The FastAPI application factory (Phase 5, §4, §20, §21).

``create_app`` builds the ASGI app from already-constructed use cases. It
constructs nothing itself — no database engine, no key pair, no
repository. Everything arrives via ``ApiServices``.

That is what keeps this layer honest about the dependency rule: the
presentation layer imports use cases and schemas, and it does not import
SQLAlchemy, psycopg, boto3 or any azure module. A test builds an app
over in-memory fakes with the same function production uses, so the
thing under test is the real application.

Wiring the concrete adapters is ``composition.py``'s job.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from application.ports.auth import TokenIssuer, TokenVerifier
from presentation.errors import register_exception_handlers
from presentation.middleware import CorrelationIdMiddleware, SecurityHeadersMiddleware
from presentation.routers import attack_paths, findings, meta, scans, scores

API_PREFIX = "/api/v1"

_DESCRIPTION = """
The authoritative Core Platform & Data Service for ComplianceIQ.

**Core owns the truth.** Findings, resources, scans and compliance scores
are produced and owned here. The AI Service reasons *over* this data via
this API and never becomes its owner; the dashboard presents it and must
keep working when the AI Service is unavailable.

### Authentication
Every `/api/v1` endpoint requires `Authorization: Bearer <JWT>` (RS256).
The **tenant is taken from the verified token** — there is no `tenant_id`
parameter anywhere in this API, and one cannot be supplied.

### Correlation
Send `X-Correlation-ID` and it is preserved and echoed; omit it and one
is generated. It appears on every response, including errors.

### Errors
Every error — including validation and unexpected failures — returns the
same envelope: `{"error": {"code", "message", "correlation_id", "details"}}`.
Branch on `code`; it is stable. `message` is for humans.

### Versioning
Breaking changes require a new prefix (`/api/v2`). Additive fields may
appear in `v1` responses, so clients must ignore unknown fields.
"""


#: A use case the API can invoke.
#:
#: Typed ``Any`` deliberately, and it is worth saying why rather than
#: leaving it to look like laziness. Each use case has a DIFFERENT
#: keyword-only ``execute`` signature (``QueryFindingsPage`` takes
#: filters and a page; ``GetFinding`` takes an id; ``SubmitScan`` takes a
#: target). A ``Protocol`` with ``execute(self, **kwargs: Any)`` is not
#: satisfied by any of them — a protocol demanding arbitrary keywords is
#: incompatible with an implementation accepting named ones — so it would
#: be a type that lies. Writing seven single-use protocols would type the
#: real use cases precisely while still excluding the two legitimate
#: substitutes: a test double and the deployment-specific
#: "not configured here" stand-in that answers 503.
#:
#: The static guarantee is not lost, only relocated: each use case
#: validates its own arguments, and the router-level contract is covered
#: by the 99 API tests that call every endpoint for real.
UseCase = Any


@dataclass(frozen=True, slots=True)
class ApiServices:
    """Everything the API needs, already constructed.

    A single explicit bundle rather than a service locator or a set of
    module-level globals: what the API depends on is enumerable by
    reading this class, and a test supplies fakes by filling it in.
    """

    query_findings: UseCase
    get_finding: UseCase
    query_attack_paths_for_scan: UseCase
    get_attack_path: UseCase
    query_scores: UseCase
    get_latest_score: UseCase
    submit_scan: UseCase
    get_scan: UseCase
    list_scans: UseCase
    token_verifier: TokenVerifier
    token_issuer: TokenIssuer | None = None
    #: Returns True when the database is reachable. Optional so a test
    #: app need not fake a database it does not use.
    health_check: Callable[[], bool] | None = None
    #: Allowed browser origins. Empty by default — a permissive default
    #: is how an API ends up readable by any site the user visits (§28).
    cors_origins: tuple[str, ...] = ()


def create_app(services: ApiServices) -> FastAPI:
    """Build the ASGI application."""

    app = FastAPI(
        title="ComplianceIQ Core API",
        version="1.0.0",
        description=_DESCRIPTION,
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        # Errors are rendered by our handlers into one envelope; FastAPI's
        # default {"detail": ...} shape never reaches a client.
        responses={},
    )

    app.state.query_findings = services.query_findings
    app.state.get_finding = services.get_finding
    app.state.query_attack_paths_for_scan = services.query_attack_paths_for_scan
    app.state.get_attack_path = services.get_attack_path
    app.state.query_scores = services.query_scores
    app.state.get_latest_score = services.get_latest_score
    app.state.submit_scan = services.submit_scan
    app.state.get_scan = services.get_scan
    app.state.list_scans = services.list_scans
    app.state.token_verifier = services.token_verifier
    app.state.token_issuer = services.token_issuer
    app.state.health_check = services.health_check

    # Order matters: middleware added last runs first. Correlation must
    # be established before anything that might log or fail, so it is
    # added last and therefore wraps everything.
    app.add_middleware(SecurityHeadersMiddleware)
    if services.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            # Never "*" together with credentials — that combination is
            # what turns a browser into a confused deputy for any site
            # the user visits.
            allow_origins=list(services.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
            expose_headers=["X-Correlation-ID"],
        )
    app.add_middleware(CorrelationIdMiddleware)

    register_exception_handlers(app)

    app.include_router(meta.router)
    app.include_router(findings.router, prefix=API_PREFIX)
    app.include_router(scores.router, prefix=API_PREFIX)
    app.include_router(scans.router, prefix=API_PREFIX)
    app.include_router(attack_paths.router, prefix=API_PREFIX)

    _apply_security_scheme(app)
    return app


def _apply_security_scheme(app: FastAPI) -> None:
    """Advertise bearer auth in OpenAPI (§21).

    Without this the generated spec documents no authentication at all,
    and a client generated from it would omit the Authorization header
    and receive 401s with no indication why.
    """

    from fastapi.openapi.utils import get_openapi

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})[
            "bearerAuth"
        ] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": (
                "RS256 JWT issued by complianceiq-core. Required claims: sub, tenant_id, "
                "roles, iss=complianceiq-core, aud=complianceiq, exp. Verify against "
                "/.well-known/jwks.json."
            ),
        }

        # Applied per-path rather than globally so the unauthenticated
        # operational endpoints are not misdocumented as requiring a token.
        for path, operations in schema.get("paths", {}).items():
            if not path.startswith(API_PREFIX):
                continue
            for operation in operations.values():
                if isinstance(operation, dict):
                    operation.setdefault("security", [{"bearerAuth": []}])

        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
