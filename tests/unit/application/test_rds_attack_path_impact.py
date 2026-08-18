"""STEP 8B — what classifying RDS as STORAGE does, and does not, do.

This is the only change in STEP 8B that alters analyzer output, so it
gets its own file.

Classifying `rds_db_instance` as `STORAGE` is a statement of fact — a
managed database is data-bearing — not a new scenario. But a role change
is exactly the kind of edit that quietly manufactures findings, so both
halves are pinned here:

* **it adds nothing spurious** — a publicly-addressable database does
  not become an attack path on its own, because `publicly_accessible` is
  deliberately not the analyzer's `public` attribute;
* **it adds the one chain that matters** — a public workload holding a
  role whose policy reaches the production database is precisely the
  flagship chain, and before this classification the analyzer could not
  see it.
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
from infrastructure.cloud.aws.normalizers.rds import normalize_rds_instance

TENANT = TenantId("acme")
ACCOUNT = "111111111111"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
REGION = "us-east-1"

DB_ARN = f"arn:aws:rds:{REGION}:{ACCOUNT}:db:prod-orders"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/app-server-role"
SG = "sg-open"


def rds(**overrides):
    instance = {
        "DBInstanceArn": DB_ARN,
        "Engine": "postgres",
        "PubliclyAccessible": False,
        "StorageEncrypted": True,
        "VpcSecurityGroups": [{"VpcSecurityGroupId": SG, "Status": "active"}],
    }
    instance.update(overrides)
    return normalize_rds_instance(
        instance=instance,
        region=REGION,
        tenant_id=TENANT,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


def resource(rid, rtype, attributes=None, relationships=()):
    return NormalizedResource(
        resource_id=ResourceId(rid),
        resource_type=rtype,
        cloud_provider=CloudProvider.AWS,
        tenant_id=TENANT,
        region=REGION,
        attributes=attributes or {},
        tags={},
        relationships=relationships,
        collected_at=NOW,
        account_id=ACCOUNT,
    )


def rel(target, kind):
    return ResourceRelationship(
        target_resource_id=ResourceId(target), relationship_type=kind
    )


def analyze(resources):
    graph = BuildResourceGraph().build(tenant_id=TENANT, resources=resources)
    return AnalyzeAttackPaths().analyze(
        tenant_id=TENANT, graph=graph, findings=(), resources=resources
    )


class TestNothingSpuriousIsAdded:
    def test_a_private_database_produces_no_path(self) -> None:
        assert analyze([rds()]) == ()

    def test_a_publicly_addressable_database_alone_produces_no_path(self) -> None:
        """The false positive avoided.

        `PubliclyAccessible: true` means the instance has a public
        endpoint — the security group still gates every packet. If this
        produced a path, every correctly firewalled public-endpoint
        database in an estate would be reported as critical.
        """

        assert analyze([rds(PubliclyAccessible=True)]) == ()

    def test_an_unencrypted_public_database_still_produces_no_path(self) -> None:
        # Bad configuration is a RULE finding, not an attack path. The
        # analyzer reports reachability, and nothing here is reachable.
        estate = [rds(PubliclyAccessible=True, StorageEncrypted=False)]
        assert analyze(estate) == ()

    def test_an_open_security_group_alone_does_not_reach_the_database(self) -> None:
        # ATTACHED_TO is informational — an attacker does not travel
        # into a security group — so an open group beside the database
        # is not a route to it.
        estate = [
            rds(PubliclyAccessible=True),
            resource(SG, "security_group", {"has_unrestricted_ingress": True}),
        ]
        assert analyze(estate) == ()


class TestTheChainThatMatters:
    def test_a_public_workload_reaching_the_database_is_found(self) -> None:
        """The reason RDS is STORAGE.

        Internet → public EC2 → IAM role → production database. Before
        this classification the analyzer walked the whole chain and then
        discarded it, because the endpoint was `OTHER` — not worth
        reaching.
        """

        estate = [
            resource(
                "i-web",
                "ec2_instance",
                {"public_ip": "203.0.113.10"},
                (rel(SG, RelationshipType.ATTACHED_TO), rel(ROLE, RelationshipType.ASSUMES)),
            ),
            resource(SG, "security_group", {"has_unrestricted_ingress": True}),
            resource(
                ROLE,
                "iam_role",
                {
                    "has_administrator_access": True,
                    "access_grants": [
                        {
                            "effect": "Allow",
                            "actions": ["rds-db:connect"],
                            "resources": [DB_ARN],
                            "has_condition": False,
                            "inverted_resources": False,
                        }
                    ],
                },
            ),
            rds(),
        ]

        paths = analyze(estate)
        flagship = [
            p for p in paths if p.scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY
        ]
        assert flagship, "the public-workload-to-database chain must be found"
        assert flagship[0].evidence["target_role"] == "storage"
        assert flagship[0].severity is Severity.CRITICAL

    def test_the_chain_names_the_database_arn(self) -> None:
        # The ARN is the identity precisely so an IAM policy resource
        # can match it. If the resource id were the bare identifier, the
        # ACCESSES edge would never form.
        estate = [
            resource(
                "i-web",
                "ec2_instance",
                {"public_ip": "203.0.113.10"},
                (rel(SG, RelationshipType.ATTACHED_TO), rel(ROLE, RelationshipType.ASSUMES)),
            ),
            resource(SG, "security_group", {"has_unrestricted_ingress": True}),
            resource(
                ROLE,
                "iam_role",
                {
                    "has_administrator_access": True,
                    "access_grants": [
                        {
                            "effect": "Allow",
                            "actions": ["rds-db:connect"],
                            "resources": [DB_ARN],
                            "has_condition": False,
                            "inverted_resources": False,
                        }
                    ],
                },
            ),
            rds(),
        ]
        flagship = next(
            p for p in analyze(estate) if p.scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY
        )
        assert DB_ARN in flagship.evidence["chain"]

    def test_a_wildcard_grant_does_not_manufacture_the_chain(self) -> None:
        # STEP 2's guard, still holding for a new resource type: a role
        # that can reach everything must not produce a path to the
        # database.
        estate = [
            resource(
                "i-web",
                "ec2_instance",
                {"public_ip": "203.0.113.10"},
                (rel(SG, RelationshipType.ATTACHED_TO), rel(ROLE, RelationshipType.ASSUMES)),
            ),
            resource(SG, "security_group", {"has_unrestricted_ingress": True}),
            resource(
                ROLE,
                "iam_role",
                {
                    "has_administrator_access": True,
                    "access_grants": [
                        {
                            "effect": "Allow",
                            "actions": ["rds-db:connect"],
                            "resources": ["*"],
                            "has_condition": False,
                            "inverted_resources": False,
                        }
                    ],
                },
            ),
            rds(),
        ]
        assert [
            p for p in analyze(estate) if p.scenario == SCENARIO_INTERNET_TO_DATA_VIA_IDENTITY
        ] == []


class TestDeterminism:
    def test_the_same_estate_produces_the_same_result(self) -> None:
        estate = [rds(PubliclyAccessible=True), resource(SG, "security_group", {})]
        runs = [
            [(str(p.id), p.risk_score) for p in analyze(estate)] for _ in range(5)
        ]
        assert all(run == runs[0] for run in runs)
