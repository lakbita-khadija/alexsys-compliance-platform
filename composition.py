"""The composition root (Phase 5, §4).

The one place concrete adapters are chosen and wired to ports. Every
other module in the system depends on abstractions; this module depends
on everything, which is exactly why it must stay the only one that does.

If you want to know what this deployment actually runs — which database,
which job runner, which key — read this file. Nothing else needs to know.

Two profiles:

* ``build_production_app`` — PostgreSQL, threaded job runner, a signing
  key loaded from the environment.
* ``build_stub_app`` — in-memory repositories and an ephemeral key. This
  is the ``core-stub`` §14 asks for, so the AI engineer can develop
  against a real API without PostgreSQL or cloud credentials.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from application.compliance.query_scores import GetLatestScore, QueryScores
from application.attack_paths.query_attack_paths import GetAttackPath, QueryAttackPathsForScan
from application.findings.query_finding_pages import GetFinding, QueryFindingsPage
from application.ports.auth import Role, TokenRequest
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.shared.enums import Severity
from domain.shared.identifiers import FindingId, ResourceId, RuleId, TenantId
from infrastructure.auth.jwt_tokens import (
    JwtSettings,
    JwtTokenIssuer,
    JwtTokenVerifier,
    RsaKeyPair,
)
from infrastructure.persistence.memory.repositories import (
    InMemoryAttackPathRepository,
    InMemoryAuditEventRepository,
    InMemoryComplianceScoreRepository,
    InMemoryFindingQueryRepository,
)
from infrastructure.system.adapters import (
    RepositoryAuditRecorder,
    SystemClock,
    UuidGenerator,
)
from presentation.app import ApiServices, create_app


def _jwt_settings() -> JwtSettings:
    return JwtSettings(
        issuer=os.environ.get("JWT_ISSUER", "complianceiq-core"),
        audience=os.environ.get("JWT_AUDIENCE", "complianceiq"),
        key_id=os.environ.get("JWT_KEY_ID", "core-1"),
    )


def _load_signing_key() -> RsaKeyPair:
    """Load the signing key from the environment.

    ``JWT_PRIVATE_KEY`` holds a PKCS#8 PEM. There is deliberately **no
    fallback to generating one**: a key generated at boot would
    invalidate every outstanding token on every restart and would differ
    between replicas, so two instances behind a load balancer would
    reject each other's tokens. Failing loudly at startup is better than
    a service that authenticates intermittently.
    """

    pem = os.environ.get("JWT_PRIVATE_KEY")
    if not pem:
        raise RuntimeError(
            "JWT_PRIVATE_KEY is not set. Generate one with:\n"
            "  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
            "-out core-signing.pem\n"
            "and provide it via the environment or a mounted secret — never a file "
            "committed to this repository."
        )
    return RsaKeyPair.from_pem(pem)


def build_production_app():
    """Wire the real service: PostgreSQL, threaded jobs, managed key."""

    from sqlalchemy import text

    from infrastructure.persistence.postgres.repositories.api_repositories import (
        PostgresAuditEventRepository,
        PostgresComplianceScoreRepository,
        PostgresFindingQueryRepository,
    )
    from infrastructure.persistence.postgres.repositories.scan_repository import (
        PostgresAttackPathRepository,
    )
    from infrastructure.persistence.postgres.session.engine import (
        DatabaseConfig,
        create_database_engine,
        create_session_factory,
    )

    settings = _jwt_settings()
    key_pair = _load_signing_key()

    engine = create_database_engine(DatabaseConfig.from_env())
    session_factory = create_session_factory(engine)

    # One session per process for the read-side repositories is NOT
    # correct for a real deployment — a per-request session scope is.
    # Wiring that requires a request-scoped dependency, which is the
    # honest remaining gap documented in the Phase 5 report.
    session = session_factory()

    findings_repo = PostgresFindingQueryRepository(session)
    attack_paths_repo = PostgresAttackPathRepository(session)
    scores_repo = PostgresComplianceScoreRepository(session)
    audit_repo = PostgresAuditEventRepository(session)

    def health_check() -> bool:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001 - any failure means "unhealthy"
            return False

    services = ApiServices(
        query_findings=QueryFindingsPage(findings_repo),
        get_finding=GetFinding(findings_repo),
        query_attack_paths_for_scan=QueryAttackPathsForScan(attack_paths_repo),
        get_attack_path=GetAttackPath(attack_paths_repo),
        query_scores=QueryScores(scores_repo),
        get_latest_score=GetLatestScore(scores_repo),
        submit_scan=_UnavailableScanSubmission(),
        get_scan=_UnavailableScanSubmission(),
        list_scans=_UnavailableScanSubmission(),
        token_verifier=JwtTokenVerifier(public_key=key_pair, settings=settings),
        token_issuer=JwtTokenIssuer(key_pair=key_pair, settings=settings),
        health_check=health_check,
        cors_origins=tuple(
            origin.strip()
            for origin in os.environ.get("CORS_ORIGINS", "").split(",")
            if origin.strip()
        ),
    )

    # Kept alive for the audit recorder, which the scan pipeline uses.
    audit = RepositoryAuditRecorder(
        repository=audit_repo, clock=SystemClock(), id_generator=UuidGenerator()
    )
    app = create_app(services)
    app.state.audit = audit
    return app


class _UnavailableScanSubmission:
    """Scan submission is not wired in the default production profile.

    Running a scan needs a configured cloud credential reference and a
    rule catalog path, which are deployment inputs this repository does
    not have. Rather than wire a half-configured pipeline that fails at
    runtime with a confusing error, submission reports 503 with a clear
    reason until an operator supplies them.

    This is a deliberate, visible gap — not an oversight. The pipeline
    itself (``SubmitScan`` / ``ScanWorker``) is implemented and tested;
    only its configuration is deployment-specific.

    As of STEP 6.5 there is a **third** required input, and it is the one
    that must not be skipped: the tenant → cloud account bindings
    (``COMPLIANCEIQ_CLOUD_ACCOUNT_BINDINGS``). A deployment that wires
    credentials and a catalog but no bindings will authenticate
    successfully and then be refused by the identity gate, because an
    empty binding set permits nothing. That is the correct direction —
    see :func:`build_cloud_identity_gate`.
    """

    def execute(self, **kwargs):  # noqa: ANN003
        from fastapi import status

        from presentation.errors import ApiError, ErrorCode

        raise ApiError(
            code=ErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "scan submission is not configured on this deployment: set the cloud "
                "credentials reference, rule catalog path and cloud account bindings"
            ),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )


def build_cloud_identity_gate(
    *,
    identity_provider,
    audit=None,
):
    """Assemble the pre-collection authentication gate (STEP 6.5).

    The one place a deployment turns configuration into the control the
    audit found missing. Bindings come from the environment, so they are
    operator configuration rather than anything the running application
    can widen.

    ``identity_provider`` is supplied by the caller because it depends on
    an already-constructed cloud session:
    ``AwsIdentityProvider(session)`` or
    ``AzureIdentityProvider(credential=..., subscription_id=...)``.

    Deliberately **not** defaulted to a permissive stub. A gate that is
    easy to omit is a gate that gets omitted, and the failure would be
    silent — scans would keep working while checking nothing.
    """

    from application.scanning.verify_cloud_identity import VerifyCloudIdentity
    from infrastructure.cloud.account_directory import EnvCloudAccountDirectory

    return VerifyCloudIdentity(
        identity_provider=identity_provider,
        directory=EnvCloudAccountDirectory(),
        audit=audit,
    )


def build_stub_app(*, seed: bool = True):
    """The core-stub for AI Service development (§14, §32).

    Real routing, real JWT verification, real tenant scoping, real error
    envelope — over in-memory data. What the AI engineer points
    ``CIQ_CORE_API_BASE_URL`` at.
    """

    settings = _jwt_settings()
    key_pair = RsaKeyPair.generate()

    findings_repo = InMemoryFindingQueryRepository()
    attack_paths_repo = InMemoryAttackPathRepository()
    scores_repo = InMemoryComplianceScoreRepository()
    audit_repo = InMemoryAuditEventRepository()

    if seed:
        for finding in _seed_findings():
            findings_repo.add(finding)

    services = ApiServices(
        query_findings=QueryFindingsPage(findings_repo),
        get_finding=GetFinding(findings_repo),
        query_attack_paths_for_scan=QueryAttackPathsForScan(attack_paths_repo),
        get_attack_path=GetAttackPath(attack_paths_repo),
        query_scores=QueryScores(scores_repo),
        get_latest_score=GetLatestScore(scores_repo),
        submit_scan=_UnavailableScanSubmission(),
        get_scan=_UnavailableScanSubmission(),
        list_scans=_UnavailableScanSubmission(),
        token_verifier=JwtTokenVerifier(public_key=key_pair, settings=settings),
        token_issuer=JwtTokenIssuer(key_pair=key_pair, settings=settings),
        health_check=lambda: True,
    )

    app = create_app(services)
    app.state.audit = RepositoryAuditRecorder(
        repository=audit_repo, clock=SystemClock(), id_generator=UuidGenerator()
    )

    # Printed on startup so the AI engineer has a working token without
    # reading any documentation. Safe: this key exists only for the life
    # of this process and grants access only to fabricated data.
    issuer = JwtTokenIssuer(key_pair=key_pair, settings=settings)
    token = issuer.issue(
        TokenRequest(
            subject="ai-service",
            tenant_id=TenantId("acme"),
            roles=frozenset({Role.READER, Role.SCANNER}),
            lifetime_seconds=86400,
        )
    )
    app.state.stub_token = token.access_token
    return app


def _seed_findings() -> list[Finding]:
    """Deterministic sample data for the stub."""

    at = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    specs = [
        ("bucket-1", "s3-bucket-public", FindingStatus.FAIL, Severity.CRITICAL, "storage"),
        ("bucket-2", "s3-bucket-no-encryption", FindingStatus.FAIL, Severity.HIGH, "encryption"),
        ("sg-1", "sg-open-to-world", FindingStatus.FAIL, Severity.CRITICAL, "network"),
        ("user-1", "iam-user-no-mfa", FindingStatus.FAIL, Severity.HIGH, "iam"),
        ("trail-1", "cloudtrail-enabled", FindingStatus.PASS, Severity.MEDIUM, "logging"),
        ("kms-1", "kms-key-rotation", FindingStatus.INDETERMINATE, Severity.MEDIUM, "encryption"),
    ]
    findings = []
    for resource, rule, status, severity, domain in specs:
        logical = f"acme:111111111111:{resource}:{rule}"
        findings.append(
            Finding(
                id=FindingId(f"{logical}:{at.isoformat()}"),
                tenant_id=TenantId("acme"),
                resource_id=ResourceId(resource),
                rule_id=RuleId(rule),
                framework="iso_27001",
                control_id="A.8.24",
                domain=domain,
                status=status,
                severity=severity,
                evidence=Evidence(data={"checked": True, "resource": resource}),
                detected_at=at,
                scan_id="acme|aws|111111111111|-|2026-06-01T12:00:00+00:00",
                region="us-east-1",
                account_id="111111111111",
                logical_finding_id=logical,
            )
        )
    return findings
