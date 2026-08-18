"""Fixtures for the Phase 5 API suite.

The app under test is built by the SAME ``create_app`` production uses,
over in-memory repositories. Only the adapters differ — routing,
authentication, tenant scoping, error handling and serialization are all
the real implementations, so a bug in any of them fails here.

Two tenants are always present. A single-tenant fixture cannot detect a
missing tenant filter: every query would return the right answer by
accident. ``acme`` and ``globex`` deliberately hold findings with
overlapping resource ids and rules.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from application.attack_paths.query_attack_paths import (
    GetAttackPath,
    QueryAttackPathsForScan,
)
from application.compliance.query_scores import (
    ComputeScoresForScan,
    GetLatestScore,
    QueryScores,
)
from application.findings.query_finding_pages import GetFinding, QueryFindingsPage
from application.ports.auth import Role, TokenRequest
from domain.findings.models import Evidence, Finding, FindingStatus
from domain.shared.enums import Severity
from domain.shared.identifiers import (
    AttackPathId,
    FindingId,
    ResourceId,
    RuleId,
    TenantId,
)
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
    FrozenClock,
    RepositoryAuditRecorder,
    SequentialIdGenerator,
)
from presentation.app import ApiServices, create_app

TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
SCAN_KEY = "acme|aws|111111111111|-|2026-06-01T12:00:00+00:00"

#: The finding and the attack path that reference each other. In
#: production both are produced by the same scan, so fixtures that named
#: each other only by accident would not exercise the correlation at all.
FLAGSHIP_PATH_ID = f"{TENANT_A!s}:internet_to_workload_to_identity_to_data:sg-1:bucket-1"
FLAGSHIP_FINDING_ID = f"{TENANT_A!s}:111111111111:bucket-1:s3-bucket-public:{NOW.isoformat()}"


def make_finding(
    *,
    tenant: TenantId = TENANT_A,
    resource: str = "bucket-1",
    rule: str = "s3-bucket-public",
    status: FindingStatus = FindingStatus.FAIL,
    severity: Severity = Severity.CRITICAL,
    framework: str = "iso_27001",
    domain: str = "storage",
    detected_at: datetime = NOW,
    account: str = "111111111111",
    scan_key: str = SCAN_KEY,
    suffix: str = "",
    attack_path_ids: tuple[str, ...] = (),
    related: tuple[str, ...] = (),
    indeterminate: tuple[str, ...] = (),
    graph_context: dict | None = None,
) -> Finding:
    logical = f"{tenant!s}:{account}:{resource}:{rule}"
    return Finding(
        id=FindingId(f"{logical}:{detected_at.isoformat()}{suffix}"),
        tenant_id=tenant,
        resource_id=ResourceId(resource),
        rule_id=RuleId(rule),
        framework=framework,
        control_id="A.8.24",
        domain=domain,
        status=status,
        severity=severity,
        evidence=Evidence(data={"public": True}),
        detected_at=detected_at,
        scan_id=scan_key,
        region="us-east-1",
        account_id=account,
        logical_finding_id=logical,
        related_attack_path_ids=tuple(AttackPathId(a) for a in attack_path_ids),
        related_resources=related,
        indeterminate_resources=indeterminate,
        graph_context=graph_context,
    )


@pytest.fixture()
def key_pair() -> RsaKeyPair:
    # 2048-bit generation is slow enough to notice per-test; one key for
    # the whole module keeps the suite fast without weakening anything.
    return _SHARED_KEY_PAIR


_SHARED_KEY_PAIR = RsaKeyPair.generate()


@pytest.fixture()
def settings() -> JwtSettings:
    return JwtSettings()


@pytest.fixture()
def issuer(key_pair: RsaKeyPair, settings: JwtSettings) -> JwtTokenIssuer:
    return JwtTokenIssuer(key_pair=key_pair, settings=settings)


@pytest.fixture()
def findings_repo() -> InMemoryFindingQueryRepository:
    repo = InMemoryFindingQueryRepository()
    repo.add(
        # Deliberately correlated with the flagship path in
        # `attack_paths_repo`: bucket-1 is that path's target, so the
        # STEP 6 round trip (finding → path → finding) is exercised
        # against ids that actually match rather than two unrelated
        # fixtures that would agree by construction.
        make_finding(
            attack_path_ids=(
                f"{TENANT_A!s}:internet_to_workload_to_identity_to_data:sg-1:bucket-1",
            ),
            # Sorted: the domain rejects unsorted or duplicated context,
            # for the same determinism reason the graph sorts everything.
            related=("i-web", "sg-1"),
            indeterminate=("kms-key-1",),
            graph_context={
                "outgoing": [
                    {
                        "relationship": "accesses",
                        "target": "bucket-1",
                        "target_type": "s3_bucket",
                        "confidence": "high",
                        "evidence": {"evidence_level": "exact"},
                    }
                ],
                "incoming": [
                    {
                        "relationship": "attached_to",
                        "source": "sg-1",
                        "source_type": "security_group",
                        "confidence": "high",
                    }
                ],
            },
        ),
        make_finding(resource="bucket-2", severity=Severity.HIGH, suffix="-b"),
        make_finding(
            resource="bucket-3",
            status=FindingStatus.PASS,
            severity=Severity.LOW,
            suffix="-c",
        ),
        make_finding(
            resource="bucket-4",
            status=FindingStatus.INDETERMINATE,
            severity=Severity.MEDIUM,
            domain="encryption",
            suffix="-d",
        ),
        # Same resource id and rule as TENANT_A's first finding, on
        # purpose: proves isolation is by tenant, not by luck.
        make_finding(tenant=TENANT_B, account="222222222222", suffix="-t2"),
    )
    return repo


def make_attack_path_row(
    *,
    tenant: TenantId = TENANT_A,
    scenario: str = "internet_to_workload_to_identity_to_data",
    source: str = "sg-1",
    target: str = "bucket-1",
    severity: str = "critical",
    risk_score: float = 92.5,
    confidence: str = "high",
    scan_key: str = SCAN_KEY,
    contributing: tuple[str, ...] = (),
) -> dict:
    """One persisted attack path, in the shape the mapper returns.

    Built by hand rather than by running the analyzer: these tests are
    about the HTTP contract, and coupling them to the analyzer's current
    output would make an unrelated scoring change fail the API suite.
    The analyzer's own output is covered by the Phase 3 unit tests.
    """

    identity = f"arn:aws:iam::111111111111:role/{target}-reader"
    return {
        # Same composite the analyzer produces, tenant first.
        "id": f"{tenant!s}:{scenario}:{source}:{target}",
        "scan_key": scan_key,
        "tenant_id": str(tenant),
        "scenario": scenario,
        "provider": "aws",
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "source": source,
        "target": target,
        "nodes": [
            {
                "resource_id": source,
                "resource_type": "security_group",
                "provider": "aws",
                "account_id": "111111111111",
                "region": "us-east-1",
                "confidence": "high",
                "kind": "collected",
            },
            {
                "resource_id": "i-web",
                "resource_type": "ec2_instance",
                "provider": "aws",
                "account_id": "111111111111",
                "region": "us-east-1",
                "confidence": "high",
                "kind": "collected",
            },
            {
                "resource_id": identity,
                "resource_type": "iam_role",
                "provider": "aws",
                "account_id": "111111111111",
                "region": None,
                "confidence": "high",
                "kind": "collected",
            },
            {
                "resource_id": target,
                "resource_type": "s3_bucket",
                "provider": "aws",
                "account_id": "111111111111",
                "region": "us-east-1",
                "confidence": "high",
                "kind": "collected",
            },
        ],
        "edges": [
            {
                "source": source,
                "target": "i-web",
                "relationship": "attached_to",
                "blocked": False,
                "confidence": "high",
                "evidence": {"has_unrestricted_ingress": True},
            },
            {
                "source": "i-web",
                "target": identity,
                "relationship": "assumes",
                "blocked": False,
                "confidence": "high",
                "evidence": {"instance_profile_arn": "arn:aws:iam::111111111111:instance-profile/app"},
            },
            {
                "source": identity,
                "target": target,
                "relationship": "accesses",
                "blocked": False,
                "confidence": confidence,
                "evidence": {"evidence_level": "exact", "matched_pattern": f"arn:aws:s3:::{target}"},
            },
        ],
        "evidence": {
            "chain": f"{source} -> i-web -> {identity} -> {target}",
            "relationships": ["assumes", "accesses"],
            "target_role": "storage",
            "score_factors": {"exposure": 30.0, "privilege": 25.0, "sensitivity": 25.0},
            "scoring_model": "v1",
        },
        "contributing_finding_ids": list(contributing),
        "algorithm_version": "v1",
        "scoring_model_version": "v1",
        "fingerprint": f"fp-{tenant!s}-{source}-{target}",
        "created_at": NOW,
    }


@pytest.fixture()
def attack_paths_repo() -> InMemoryAttackPathRepository:
    repo = InMemoryAttackPathRepository()
    # Names the failing finding on its target, exactly as the analyzer
    # does: `contributing_finding_ids` is FAIL-only, so the passing and
    # indeterminate findings elsewhere in the fixture set correctly do
    # NOT appear here.
    repo.add(make_attack_path_row(contributing=(FLAGSHIP_FINDING_ID,)))
    repo.add(
        make_attack_path_row(
            scenario="public_identity_with_privilege",
            source="arn:aws:iam::111111111111:role/public",
            target="bucket-2",
            severity="high",
            risk_score=80.0,
            confidence="medium",
        )
    )
    repo.add(
        make_attack_path_row(
            scenario="internet_to_sensitive_data",
            source="sg-3",
            target="bucket-3",
            severity="medium",
            risk_score=55.0,
            confidence="low",
        )
    )
    # Tenant B, same scenario and same source/target names, so the id
    # differs only by its tenant prefix — a missing tenant filter shows
    # up as a leak rather than as an empty result.
    repo.add(make_attack_path_row(tenant=TENANT_B, scan_key=SCAN_KEY))
    return repo


@pytest.fixture()
def scores_repo() -> InMemoryComplianceScoreRepository:
    return InMemoryComplianceScoreRepository()


@pytest.fixture()
def audit_repo() -> InMemoryAuditEventRepository:
    return InMemoryAuditEventRepository()


@pytest.fixture()
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture()
def audit(audit_repo, clock) -> RepositoryAuditRecorder:
    return RepositoryAuditRecorder(
        repository=audit_repo, clock=clock, id_generator=SequentialIdGenerator("evt")
    )


@pytest.fixture()
def app(findings_repo, scores_repo, attack_paths_repo, key_pair, settings, clock, audit):
    """The real application, over in-memory adapters."""

    scan_stub = _ScanStub()
    services = ApiServices(
        query_findings=QueryFindingsPage(findings_repo),
        get_finding=GetFinding(findings_repo),
        query_scores=QueryScores(scores_repo),
        get_latest_score=GetLatestScore(scores_repo),
        query_attack_paths_for_scan=QueryAttackPathsForScan(attack_paths_repo),
        get_attack_path=GetAttackPath(attack_paths_repo),
        submit_scan=scan_stub,
        get_scan=scan_stub,
        list_scans=scan_stub,
        token_verifier=JwtTokenVerifier(public_key=key_pair, settings=settings),
        token_issuer=JwtTokenIssuer(key_pair=key_pair, settings=settings),
        health_check=lambda: True,
    )
    application = create_app(services)
    application.state.compute_scores = ComputeScoresForScan(scores_repo)
    application.state.scan_stub = scan_stub
    return application


class _ScanStub:
    """Stands in for the scan use cases.

    The scan pipeline's own behaviour is covered by its unit tests and by
    the Phase 4 persistence suite; what the API tests need is the HTTP
    contract around it — 202, 409, tenant-scoped 404.
    """

    def __init__(self) -> None:
        self.scans: dict[tuple[str, str], object] = {}
        self.submitted: list[object] = []
        self.conflict = False

    def execute(self, **kwargs):  # noqa: ANN003 - shape varies by use case
        from application.scanning.submit_scan import ScanConflict, ScanSubmission
        from domain.scans.models import ScanStatus

        identity = kwargs["identity"]

        if "target" in kwargs:  # SubmitScan
            identity.require_role(Role.SCANNER)
            if self.conflict:
                raise ScanConflict("a scan for this target is already running")
            submission = ScanSubmission(
                scan_key=SCAN_KEY,
                status=ScanStatus.QUEUED,
                tenant_id=identity.tenant_id,
                submitted_at=NOW,
            )
            self.submitted.append(submission)
            return submission

        identity.require_role(Role.READER)
        if "scan_key" in kwargs:  # GetScan
            return self.scans.get((str(identity.tenant_id), kwargs["scan_key"]))
        return tuple(  # ListScans
            v for (t, _), v in self.scans.items() if t == str(identity.tenant_id)
        )


@pytest.fixture()
def client(app) -> TestClient:
    # raise_server_exceptions=False so an unhandled exception is rendered
    # by our 500 handler and asserted on, rather than propagating into
    # the test and hiding whether the envelope is correct.
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def token_factory(issuer):
    def _make(
        *,
        tenant: TenantId = TENANT_A,
        subject: str = "ai-service",
        roles: frozenset[Role] = frozenset({Role.READER}),
        lifetime: int = 3600,
    ) -> str:
        return issuer.issue(
            TokenRequest(
                subject=subject, tenant_id=tenant, roles=roles, lifetime_seconds=lifetime
            )
        ).access_token

    return _make


@pytest.fixture()
def auth_headers(token_factory):
    return {"Authorization": f"Bearer {token_factory()}"}


@pytest.fixture()
def scanner_headers(token_factory):
    return {
        "Authorization": f"Bearer {token_factory(roles=frozenset({Role.READER, Role.SCANNER}))}"
    }
