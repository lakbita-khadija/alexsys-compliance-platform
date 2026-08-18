"""STEP 3 — the flagship attack path, end to end.

    Internet → Public Workload → IAM Identity → Sensitive Resource

The chain a CSPM exists to find. It was unevidenced until STEP 1 supplied
`workload --ASSUMES--> identity` from `iam:GetInstanceProfile` and STEP 2
supplied `identity --ACCESSES--> resource` from matched IAM policy
grants.

Every negative test here guards a way the chain could be reported
*without* being real — which remains the more expensive failure.
"""

from __future__ import annotations

from datetime import datetime, timezone


from application.attack_paths.analyze_attack_paths import (
    SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY,
    AnalyzeAttackPaths,
)
from application.graph.build_resource_graph import BuildResourceGraph
from domain.resources.models import NormalizedResource, ResourceRelationship
from domain.shared.enums import CloudProvider, RelationshipType, Severity
from domain.shared.identifiers import ResourceId, TenantId

TENANT = TenantId("acme")
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ACCOUNT = "111111111111"
RT = RelationshipType

ROLE = f"arn:aws:iam::{ACCOUNT}:role/app-server-role"


def resource(rid, rtype, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region="us-east-1",
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


def rel(target, kind):
    return ResourceRelationship(target_resource_id=ResourceId(target), relationship_type=kind)


def grant(resources, actions=("s3:GetObject",), effect="Allow", **kw):
    return {
        "effect": effect,
        "actions": list(actions),
        "resources": list(resources),
        "has_condition": kw.get("has_condition", False),
        "inverted_resources": kw.get("inverted_resources", False),
    }


def estate(
    *,
    public_ip="203.0.113.10",
    open_ingress=True,
    assumes=True,
    grants=None,
    admin=True,
):
    """The full chain, with each link independently switchable."""

    workload_rels = [rel("sg-1", RT.ATTACHED_TO)]
    if assumes:
        workload_rels.append(rel(ROLE, RT.ASSUMES))

    return [
        resource("i-web", "ec2_instance", {"public_ip": public_ip}, tuple(workload_rels)),
        resource("sg-1", "security_group", {"has_unrestricted_ingress": open_ingress}),
        resource(
            ROLE,
            "iam_role",
            {
                "has_administrator_access": admin,
                "access_grants": grants
                if grants is not None
                else [grant(["arn:aws:s3:::acme-reports"])],
            },
        ),
        resource("acme-reports", "s3_bucket", {"public": False}),
        resource("unrelated-bucket", "s3_bucket", {"public": False}),
    ]


def analyze(resources):
    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    return AnalyzeAttackPaths().analyze(
        tenant_id=TENANT, graph=graph, findings=(), resources=resources
    )


def flagship(paths):
    return next(
        (p for p in paths if p.scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY), None
    )


class TestTheFlagshipPathIsFound:
    def test_the_complete_chain_is_reported(self) -> None:
        path = flagship(analyze(estate()))
        assert path is not None

    def test_the_chain_reads_correctly(self) -> None:
        path = flagship(analyze(estate()))
        assert path.evidence["chain"] == f"sg-1 -> i-web -> {ROLE} -> acme-reports"

    def test_it_is_critical(self) -> None:
        path = flagship(analyze(estate()))
        assert path.severity is Severity.CRITICAL
        assert path.risk_score >= 70

    def test_every_hop_is_named_in_the_evidence(self) -> None:
        path = flagship(analyze(estate()))
        assert path.evidence["exposure_evidence"] == [
            "public_ip",
            "has_unrestricted_ingress",
        ]
        assert "has_administrator_access" in path.evidence["privilege_evidence"]
        assert path.evidence["relationships"] == ["assumes", "accesses"]
        assert path.evidence["target_role"] == "storage"

    def test_it_outranks_the_partial_scenarios(self) -> None:
        paths = analyze(estate())
        assert paths[0].scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY

    def test_only_the_named_bucket_is_reached(self) -> None:
        # `unrelated-bucket` is not named by the policy, so no path.
        for path in analyze(estate()):
            assert "unrelated-bucket" not in path.evidence["chain"]


class TestEveryLinkIsRequired:
    """Remove one link; the chain must disappear."""

    def test_no_public_address_no_chain(self) -> None:
        assert flagship(analyze(estate(public_ip=None))) is None

    def test_no_open_ingress_no_chain(self) -> None:
        assert flagship(analyze(estate(open_ingress=False))) is None

    def test_no_identity_edge_no_chain(self) -> None:
        # This is STEP 1's contribution. Without it the chain is exactly
        # as unevidenced as it was before.
        assert flagship(analyze(estate(assumes=False))) is None

    def test_no_policy_grant_no_chain(self) -> None:
        assert flagship(analyze(estate(grants=[]))) is None

    def test_wildcard_grant_does_not_manufacture_the_chain(self) -> None:
        # STEP 2's central guard, exercised at the attack path level: a
        # role that can reach EVERYTHING must not produce a path to
        # every bucket.
        assert flagship(analyze(estate(grants=[grant(["*"])]))) is None

    def test_explicit_deny_removes_the_chain(self) -> None:
        grants = [
            grant(["arn:aws:s3:::acme-*"]),
            grant(["arn:aws:s3:::acme-reports"], effect="Deny"),
        ]
        assert flagship(analyze(estate(grants=grants))) is None


class TestNarrativeHonesty:
    def test_a_direct_workload_to_data_edge_is_not_called_an_identity_chain(self) -> None:
        """Guards the scenario's own claim.

        If a workload could reach data without passing through an
        identity, reporting it here would name a privilege hop that never
        happened — a true risk described by a false sentence, the same
        class of defect as the identity/data-bearing bug.
        """

        direct = [
            resource(
                "i-web",
                "ec2_instance",
                {"public_ip": "203.0.113.10"},
                (rel("sg-1", RT.ATTACHED_TO), rel("acme-reports", RT.ACCESSES)),
            ),
            resource("sg-1", "security_group", {"has_unrestricted_ingress": True}),
            resource("acme-reports", "s3_bucket", {"public": False}),
        ]
        assert flagship(analyze(direct)) is None

    def test_a_non_data_target_is_not_reported(self) -> None:
        # Reaching another workload is not the objective.
        grants = [grant(["i-other"])]
        with_workload = estate(grants=grants) + [
            resource("i-other", "ec2_instance", {})
        ]
        assert flagship(analyze(with_workload)) is None


class TestConfidenceAndIncompleteness:
    def test_a_conditioned_grant_lowers_path_confidence(self) -> None:
        grants = [grant(["arn:aws:s3:::acme-reports"], has_condition=True)]
        path = flagship(analyze(estate(grants=grants)))

        # Weakest link: the ACCESSES edge dropped to medium, so the path
        # does too.
        assert path is not None
        assert path.confidence == "medium"

    def test_undetermined_privilege_is_flagged(self) -> None:
        from domain.shared.unknown import UNKNOWN

        resources = estate()
        resources[2] = resource(
            ROLE,
            "iam_role",
            {
                "has_administrator_access": UNKNOWN,
                "access_grants": [grant(["arn:aws:s3:::acme-reports"])],
            },
        )
        path = flagship(analyze(resources))

        assert path is not None
        assert path.evidence["privilege_evidence"] == []
        assert path.evidence["evidence_incomplete"] is True


class TestDeterminism:
    def test_same_estate_same_result(self) -> None:
        runs = [
            [(str(p.id), p.risk_score, p.severity) for p in analyze(estate())]
            for _ in range(5)
        ]
        assert all(run == runs[0] for run in runs)

    def test_input_order_does_not_matter(self) -> None:
        forward = [(str(p.id), p.risk_score) for p in analyze(estate())]
        backward = [(str(p.id), p.risk_score) for p in analyze(list(reversed(estate())))]
        assert forward == backward

    def test_path_id_is_stable(self) -> None:
        first = flagship(analyze(estate()))
        second = flagship(analyze(estate()))
        assert str(first.id) == str(second.id)
