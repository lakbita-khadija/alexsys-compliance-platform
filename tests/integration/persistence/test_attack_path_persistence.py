"""Attack path persistence against a real PostgreSQL server (STEP 4).

The paths under test are produced by the REAL analyzer over a real
resource graph, not hand-built. Every earlier defect in this project
lived in a seam — components correct in isolation, wrong in composition —
and `AnalyzeAttackPaths` → `ResourceGraph` → `attack_path_to_row` →
JSONB → `attack_path_row_to_summary` is four seams in a row. A fixture
that skips the first two would test the last two against a shape nothing
produces.

What only a real database can show: JSONB round-tripping of the nested
node/edge lists, the CHECK constraints actually rejecting an
out-of-range score, ON CONFLICT making a re-persist idempotent, the
CASCADE from `scans`, and rollback leaving nothing behind.
"""

from __future__ import annotations


import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from application.attack_paths.analyze_attack_paths import (
    SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY,
    AnalyzeAttackPaths,
)
from application.graph.build_resource_graph import BuildResourceGraph
from application.scanning.dtos import ScanResult
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType
from domain.shared.identifiers import ResourceId
from infrastructure.persistence.postgres.mappers.mappers import attack_path_to_row
from tests.integration.persistence.test_persistence import (
    AWS_TARGET_B,
    T1,
    T2,
    TENANT_A,
    TENANT_B,
    persist,
)

RT = RelationshipType
ROLE_A = "arn:aws:iam::111111111111:role/app-server-role"
ROLE_B = "arn:aws:iam::222222222222:role/app-server-role"


# ---------------------------------------------------------------------
# Builders — a real estate that the real analyzer finds a real path in
# ---------------------------------------------------------------------


def _resource(rid, rtype, *, tenant, account, attributes=None, relationships=(), at=T1):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=tenant,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=at,
        account_id=account,
    )


def flagship_estate(*, tenant=TENANT_A, account="111111111111", role=ROLE_A, at=T1):
    """Internet → public EC2 → IAM role → S3 bucket.

    The chain STEP 1 and STEP 2 made evidenceable, which is the one worth
    proving survives a database round trip.
    """

    def rel(target, kind):
        return ResourceRelationship(target_resource_id=ResourceId(target), relationship_type=kind)

    bucket = f"{tenant!s}-reports"
    return [
        _resource(
            "i-web",
            "ec2_instance",
            tenant=tenant,
            account=account,
            attributes={"public_ip": "203.0.113.10"},
            relationships=(rel("sg-1", RT.ATTACHED_TO), rel(role, RT.ASSUMES)),
            at=at,
        ),
        _resource(
            "sg-1",
            "security_group",
            tenant=tenant,
            account=account,
            attributes={"has_unrestricted_ingress": True},
            at=at,
        ),
        _resource(
            role,
            "iam_role",
            tenant=tenant,
            account=account,
            attributes={
                "has_administrator_access": True,
                "access_grants": [
                    {
                        "effect": "Allow",
                        "actions": ["s3:GetObject"],
                        "resources": [f"arn:aws:s3:::{bucket}"],
                        "has_condition": False,
                        "inverted_resources": False,
                    }
                ],
            },
            at=at,
        ),
        _resource(bucket, "s3_bucket", tenant=tenant, account=account, attributes={"public": False}, at=at),
    ]


def a_result_with_paths(*, tenant=TENANT_A, account="111111111111", role=ROLE_A, at=T1):
    resources = flagship_estate(tenant=tenant, account=account, role=role, at=at)
    graph = BuildResourceGraph().build(tenant_id=tenant, resources=resources)
    paths = AnalyzeAttackPaths().analyze(
        tenant_id=tenant, graph=graph, findings=(), resources=resources
    )
    assert paths, "the fixture estate must actually produce attack paths"
    return ScanResult(
        scan_id=f"legacy:{at.isoformat()}",
        tenant_id=tenant,
        provider=CloudProvider.AWS,
        scanned_at=at,
        resources=tuple(resources),
        graph=graph,
        findings=(),
        attack_paths=paths,
        drift_events=(),
    )


@pytest.fixture()
def stored(uow):
    """One scan's worth of real attack paths, persisted."""

    result = a_result_with_paths()
    outcome = persist(uow, result)
    return outcome.scan_key, result


# ---------------------------------------------------------------------


class TestTheyReachTheDatabaseAtAll:
    def test_the_scan_pipeline_writes_them(self, uow, stored) -> None:
        # The regression this whole step exists for: PersistScanResult
        # computed attack paths and then dropped them on the floor.
        scan_key, result = stored
        with uow as u:
            rows = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=scan_key)
        assert len(rows) == len(result.attack_paths)

    def test_the_flagship_path_is_among_them(self, uow, stored) -> None:
        scan_key, _ = stored
        with uow as u:
            rows = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=scan_key)
        assert SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY in {r["scenario"] for r in rows}

    def test_highest_risk_first(self, uow, stored) -> None:
        scan_key, _ = stored
        with uow as u:
            rows = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=scan_key)
        scores = [r["risk_score"] for r in rows]
        assert scores == sorted(scores, reverse=True)


class TestJsonbRoundTrip:
    def test_the_chain_survives_intact_and_in_order(self, uow, stored) -> None:
        # Order is the load-bearing property: a path whose hops reorder is
        # a different path, and JSONB preserves array order (unlike the
        # object-key order it does not).
        scan_key, result = stored
        original = next(
            p for p in result.attack_paths
            if p.scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY
        )
        with uow as u:
            row = u.attack_paths.get_by_id(tenant_id=TENANT_A, attack_path_id=str(original.id))

        assert [n["resource_id"] for n in row["nodes"]] == [
            str(n.resource_id) for n in original.nodes
        ]
        assert [e["relationship"] for e in row["edges"]] == [
            e.relationship_type.value for e in original.edges
        ]

    def test_the_evidence_survives(self, uow, stored) -> None:
        scan_key, result = stored
        original = next(
            p for p in result.attack_paths
            if p.scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY
        )
        with uow as u:
            row = u.attack_paths.get_by_id(tenant_id=TENANT_A, attack_path_id=str(original.id))

        assert row["evidence"]["chain"] == original.evidence["chain"]
        assert row["evidence"]["relationships"] == list(original.evidence["relationships"])

    def test_scoring_and_severity_survive(self, uow, stored) -> None:
        scan_key, result = stored
        original = result.attack_paths[0]
        with uow as u:
            row = u.attack_paths.get_by_id(tenant_id=TENANT_A, attack_path_id=str(original.id))

        assert row["risk_score"] == original.risk_score
        assert row["severity"] == original.severity.value
        assert row["confidence"] == original.confidence
        assert row["algorithm_version"] == original.algorithm_version

    def test_the_stored_timestamp_is_the_scans_own(self, uow, stored) -> None:
        # Not the wall clock at write time: the row records when the
        # cloud was in this state.
        scan_key, result = stored
        with uow as u:
            rows = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=scan_key)
        assert {r["created_at"] for r in rows} == {T1}


class TestIdempotence:
    def test_re_persisting_the_same_scan_does_not_duplicate(self, uow) -> None:
        # Path ids are deterministic composites, so a retried persist
        # collides by design. It must be a no-op, not a crash and not a
        # second copy.
        result = a_result_with_paths()
        first = persist(uow, result)
        with uow as u:
            before = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=first.scan_key)

        with uow as u:
            u.attack_paths.save_all(
                tenant_id=TENANT_A,
                scan_key=first.scan_key,
                attack_paths=result.attack_paths,
                created_at=T1,
            )
            u.commit()

        with uow as u:
            after = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=first.scan_key)
        assert [r["id"] for r in after] == [r["id"] for r in before]

    def test_saving_no_paths_is_a_no_op(self, uow, stored) -> None:
        scan_key, _ = stored
        with uow as u:
            assert u.attack_paths.save_all(
                tenant_id=TENANT_A, scan_key=scan_key, attack_paths=(), created_at=T1
            ) == 0

    def test_the_same_path_in_two_scans_is_two_rows(self, uow) -> None:
        # The composite primary key's whole purpose: unchanged
        # infrastructure produces the SAME path id every scan, and keying
        # on the id alone would silently destroy the history.
        first = persist(uow, a_result_with_paths(at=T1))
        second = persist(uow, a_result_with_paths(at=T2))
        assert first.scan_key != second.scan_key

        with uow as u:
            rows_1 = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=first.scan_key)
            rows_2 = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=second.scan_key)

        assert {r["id"] for r in rows_1} == {r["id"] for r in rows_2}
        assert rows_1[0]["created_at"] != rows_2[0]["created_at"]

    def test_the_fingerprint_is_stable_across_scans(self, uow) -> None:
        # "Is this the same path as last week" must survive a re-scoring,
        # so the fingerprint excludes the score.
        first = persist(uow, a_result_with_paths(at=T1))
        second = persist(uow, a_result_with_paths(at=T2))
        with uow as u:
            a = {r["id"]: r["fingerprint"] for r in u.attack_paths.get_for_scan(
                tenant_id=TENANT_A, scan_key=first.scan_key)}
            b = {r["id"]: r["fingerprint"] for r in u.attack_paths.get_for_scan(
                tenant_id=TENANT_A, scan_key=second.scan_key)}
        assert a == b


class TestTenantIsolation:
    def test_a_tenant_reads_only_its_own_paths(self, uow) -> None:
        a = persist(uow, a_result_with_paths(tenant=TENANT_A))
        b = persist(
            uow,
            a_result_with_paths(tenant=TENANT_B, account="222222222222", role=ROLE_B),
            target=AWS_TARGET_B,
        )

        with uow as u:
            rows_a = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=a.scan_key)
            rows_b = u.attack_paths.get_for_scan(tenant_id=TENANT_B, scan_key=b.scan_key)

        assert {r["tenant_id"] for r in rows_a} == {"acme"}
        assert {r["tenant_id"] for r in rows_b} == {"globex"}

    def test_a_foreign_scan_key_returns_nothing(self, uow) -> None:
        # The query a scan_key-only WHERE clause would answer wrongly.
        b = persist(
            uow,
            a_result_with_paths(tenant=TENANT_B, account="222222222222", role=ROLE_B),
            target=AWS_TARGET_B,
        )
        with uow as u:
            assert u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=b.scan_key) == ()

    def test_a_foreign_path_id_returns_none(self, uow) -> None:
        b = persist(
            uow,
            a_result_with_paths(tenant=TENANT_B, account="222222222222", role=ROLE_B),
            target=AWS_TARGET_B,
        )
        with uow as u:
            foreign = u.attack_paths.get_for_scan(tenant_id=TENANT_B, scan_key=b.scan_key)[0]
            assert u.attack_paths.get_by_id(
                tenant_id=TENANT_A, attack_path_id=foreign["id"]
            ) is None


class TestConstraintsAreEnforcedByTheDatabase:
    """The aggregate rejects these; so must the table.

    An invariant enforced only in Python is enforced only by the code
    paths that happen to go through Python — not by a migration, a
    backfill, or an operator with psql open.
    """

    def _raw_insert(self, session_factory, uow, **overrides):
        result = a_result_with_paths()
        outcome = persist(uow, result)
        row = attack_path_to_row(result.attack_paths[0], scan_key=outcome.scan_key, created_at=T1)
        row["attack_path_id"] = "forced-row"
        row.update(overrides)

        import json

        with session_factory() as session:
            session.execute(
                text(
                    "INSERT INTO attack_paths (attack_path_id, scan_key, tenant_id, scenario,"
                    " provider, severity, risk_score, confidence, source_id, target_id, nodes,"
                    " edges, evidence, contributing_finding_ids, algorithm_version,"
                    " scoring_model_version, fingerprint, created_at)"
                    " VALUES (:attack_path_id, :scan_key, :tenant_id, :scenario, :provider,"
                    " :severity, :risk_score, :confidence, :source_id, :target_id,"
                    " CAST(:nodes AS jsonb), CAST(:edges AS jsonb), CAST(:evidence AS jsonb),"
                    " CAST(:contributing_finding_ids AS jsonb), :algorithm_version,"
                    " :scoring_model_version, :fingerprint, :created_at)"
                ),
                {
                    **row,
                    "nodes": json.dumps(row["nodes"]),
                    "edges": json.dumps(row["edges"]),
                    "evidence": json.dumps(row["evidence"]),
                    "contributing_finding_ids": json.dumps(row["contributing_finding_ids"]),
                },
            )
            session.commit()

    def test_an_unknown_severity_is_rejected(self, uow, session_factory) -> None:
        with pytest.raises(IntegrityError):
            self._raw_insert(session_factory, uow, severity="catastrophic")

    def test_a_score_above_100_is_rejected(self, uow, session_factory) -> None:
        with pytest.raises(IntegrityError):
            self._raw_insert(session_factory, uow, risk_score=101.0)

    def test_a_negative_score_is_rejected(self, uow, session_factory) -> None:
        with pytest.raises(IntegrityError):
            self._raw_insert(session_factory, uow, risk_score=-1.0)

    def test_an_unknown_confidence_is_rejected(self, uow, session_factory) -> None:
        with pytest.raises(IntegrityError):
            self._raw_insert(session_factory, uow, confidence="certain")

    def test_a_valid_row_is_accepted(self, uow, session_factory) -> None:
        # Without this the four tests above would pass just as happily if
        # the INSERT were malformed for some unrelated reason.
        self._raw_insert(session_factory, uow)

    def test_a_path_for_an_unknown_scan_is_rejected(self, uow, session_factory) -> None:
        with pytest.raises(IntegrityError):
            self._raw_insert(session_factory, uow, scan_key="no-such-scan")


class TestTransactionalSafety:
    def test_a_rolled_back_unit_of_work_leaves_nothing(self, uow, session_factory) -> None:
        result = a_result_with_paths()
        outcome = persist(uow, result)

        with pytest.raises(RuntimeError):
            with uow as u:
                u.attack_paths.save_all(
                    tenant_id=TENANT_A,
                    scan_key=outcome.scan_key,
                    attack_paths=result.attack_paths,
                    created_at=T2,
                )
                raise RuntimeError("something failed after the write")

        # The original rows are intact and the aborted write left no trace.
        with uow as u:
            rows = u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=outcome.scan_key)
        assert {r["created_at"] for r in rows} == {T1}

    def test_deleting_the_scan_cascades(self, uow, session_factory) -> None:
        # A path without its scan is an orphan nobody can interpret.
        result = a_result_with_paths()
        outcome = persist(uow, result)

        with session_factory() as session:
            session.execute(
                text("DELETE FROM scans WHERE scan_key = :k"), {"k": outcome.scan_key}
            )
            session.commit()

        with uow as u:
            assert u.attack_paths.get_for_scan(
                tenant_id=TENANT_A, scan_key=outcome.scan_key
            ) == ()


class TestDeterminism:
    def test_two_identical_scans_store_identical_paths(self, uow) -> None:
        first = persist(uow, a_result_with_paths(at=T1))
        second = persist(uow, a_result_with_paths(at=T2))

        with uow as u:
            a = [
                (r["id"], r["risk_score"], r["severity"], r["confidence"])
                for r in u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=first.scan_key)
            ]
            b = [
                (r["id"], r["risk_score"], r["severity"], r["confidence"])
                for r in u.attack_paths.get_for_scan(tenant_id=TENANT_A, scan_key=second.scan_key)
            ]
        assert a == b
