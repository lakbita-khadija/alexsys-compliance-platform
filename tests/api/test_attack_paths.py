"""STEP 5 — the attack path endpoints, over the real app.

Two things are being tested, and only the second is about HTTP:

* **isolation** — an attack path names the exact resources an attacker
  would traverse. Leaking one across tenants is worse than leaking a
  finding, because it is a ready-made attack plan for infrastructure the
  reader does not own. Tenant B holds a path whose id differs from tenant
  A's only by its prefix, so a missing filter surfaces as a leak.
* **the contract** — ordering, the severity summary, the filters, and the
  fact that the scoring breakdown actually reaches the client. A score
  nobody can defend is a number, not evidence.
"""

from __future__ import annotations

import pytest

from application.ports.auth import Role
from tests.api.conftest import SCAN_KEY, TENANT_A, TENANT_B

LIST = f"/api/v1/scans/{SCAN_KEY}/attack-paths"
FLAGSHIP = f"{TENANT_A!s}:internet_to_workload_to_identity_to_data:sg-1:bucket-1"
FOREIGN = f"{TENANT_B!s}:internet_to_workload_to_identity_to_data:sg-1:bucket-1"


@pytest.fixture()
def headers_a(token_factory):
    return {"Authorization": f"Bearer {token_factory(tenant=TENANT_A)}"}


@pytest.fixture()
def headers_b(token_factory):
    return {"Authorization": f"Bearer {token_factory(tenant=TENANT_B)}"}


class TestScanScopedList:
    def test_a_tenant_sees_its_own_paths(self, client, headers_a) -> None:
        body = client.get(LIST, headers=headers_a).json()
        assert body["summary"]["total"] == 3
        assert {item["tenant_id"] for item in body["items"]} == {"acme"}

    def test_the_other_tenant_sees_only_its_own(self, client, headers_b) -> None:
        body = client.get(LIST, headers=headers_b).json()
        assert body["summary"]["total"] == 1
        assert {item["tenant_id"] for item in body["items"]} == {"globex"}

    def test_highest_risk_first(self, client, headers_a) -> None:
        # An unordered list of attack paths is a list of things nobody
        # will read past the tenth of.
        scores = [item["risk_score"] for item in client.get(LIST, headers=headers_a).json()["items"]]
        assert scores == sorted(scores, reverse=True)
        assert scores[0] == 92.5

    def test_the_summary_counts_match_the_items(self, client, headers_a) -> None:
        body = client.get(LIST, headers=headers_a).json()
        summary = body["summary"]
        assert summary == {"critical": 1, "high": 1, "medium": 1, "low": 0, "total": 3}
        assert len(body["items"]) == summary["total"]

    def test_an_unknown_scan_returns_an_empty_list_not_an_error(
        self, client, headers_a
    ) -> None:
        # A 404 here would tell a caller which scan keys exist.
        body = client.get("/api/v1/scans/no-such-scan/attack-paths", headers=headers_a).json()
        assert body["items"] == []
        assert body["summary"]["total"] == 0

    def test_a_reader_role_is_required(self, client, token_factory) -> None:
        headers = {"Authorization": f"Bearer {token_factory(roles=frozenset())}"}
        assert client.get(LIST, headers=headers).status_code == 403

    def test_admin_does_not_implicitly_grant_reader(self, client, token_factory) -> None:
        headers = {"Authorization": f"Bearer {token_factory(roles=frozenset({Role.ADMIN}))}"}
        assert client.get(LIST, headers=headers).status_code == 403


class TestFilters:
    def test_severity(self, client, headers_a) -> None:
        body = client.get(f"{LIST}?severity=critical", headers=headers_a).json()
        assert [i["severity"] for i in body["items"]] == ["critical"]
        assert body["summary"]["total"] == 1

    def test_scenario(self, client, headers_a) -> None:
        body = client.get(
            f"{LIST}?scenario=public_identity_with_privilege", headers=headers_a
        ).json()
        assert [i["scenario"] for i in body["items"]] == ["public_identity_with_privilege"]

    def test_min_confidence_excludes_weaker_evidence(self, client, headers_a) -> None:
        # The point of the filter: a conditioned IAM grant produces a
        # low-confidence path, and a responder triaging at 3am should be
        # able to say "only show me what we are sure of".
        body = client.get(f"{LIST}?min_confidence=medium", headers=headers_a).json()
        assert {i["confidence"] for i in body["items"]} == {"high", "medium"}

    def test_min_confidence_high_is_the_strictest(self, client, headers_a) -> None:
        body = client.get(f"{LIST}?min_confidence=high", headers=headers_a).json()
        assert [i["confidence"] for i in body["items"]] == ["high"]

    def test_filters_compose(self, client, headers_a) -> None:
        body = client.get(
            f"{LIST}?severity=critical&min_confidence=high", headers=headers_a
        ).json()
        assert body["summary"]["total"] == 1

    def test_the_summary_reflects_the_filter(self, client, headers_a) -> None:
        # If the summary were computed before filtering, the dashboard
        # would show a count that contradicts the list beneath it.
        body = client.get(f"{LIST}?severity=medium", headers=headers_a).json()
        assert body["summary"] == {
            "critical": 0,
            "high": 0,
            "medium": 1,
            "low": 0,
            "total": 1,
        }

    @pytest.mark.parametrize(
        "query",
        [
            "severity=catastrophic",
            "min_confidence=certain",
            "severity=CRITICAL",
        ],
    )
    def test_unknown_enum_values_are_rejected(self, client, headers_a, query) -> None:
        response = client.get(f"{LIST}?{query}", headers=headers_a)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"

    def test_a_tenant_id_parameter_cannot_change_scope(self, client, headers_a) -> None:
        body = client.get(f"{LIST}?tenant_id=globex", headers=headers_a).json()
        assert {i["tenant_id"] for i in body["items"]} == {"acme"}


class TestSinglePath:
    def test_the_full_chain_is_returned(self, client, headers_a) -> None:
        body = client.get(f"/api/v1/attack-paths/{FLAGSHIP}", headers=headers_a).json()
        assert body["id"] == FLAGSHIP
        assert [n["resource_id"] for n in body["nodes"]] == [
            "sg-1",
            "i-web",
            "arn:aws:iam::111111111111:role/bucket-1-reader",
            "bucket-1",
        ]

    def test_the_edges_name_the_relationships_in_order(self, client, headers_a) -> None:
        body = client.get(f"/api/v1/attack-paths/{FLAGSHIP}", headers=headers_a).json()
        assert [e["relationship"] for e in body["edges"]] == [
            "attached_to",
            "assumes",
            "accesses",
        ]

    def test_the_scoring_breakdown_reaches_the_client(self, client, headers_a) -> None:
        body = client.get(f"/api/v1/attack-paths/{FLAGSHIP}", headers=headers_a).json()
        assert body["evidence"]["score_factors"] == {
            "exposure": 30.0,
            "privilege": 25.0,
            "sensitivity": 25.0,
        }
        assert body["scoring_model_version"] == "v1"
        assert body["algorithm_version"] == "v1"

    def test_the_fingerprint_is_exposed(self, client, headers_a) -> None:
        # Without it a client cannot tell "the same path, rescored" from
        # "a new path".
        body = client.get(f"/api/v1/attack-paths/{FLAGSHIP}", headers=headers_a).json()
        assert body["fingerprint"] == "fp-acme-sg-1-bucket-1"

    def test_a_nonexistent_path_is_404(self, client, headers_a) -> None:
        response = client.get("/api/v1/attack-paths/no-such-path", headers=headers_a)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


class TestTenantIsolation:
    def test_another_tenants_path_is_404_even_with_the_exact_id(
        self, client, headers_a, headers_b
    ) -> None:
        # FOREIGN is a real, resolvable id — for globex. Trivially
        # guessable too, since the composite is tenant-prefixed. That is
        # exactly why the filter, not the obscurity, has to hold.
        assert client.get(f"/api/v1/attack-paths/{FOREIGN}", headers=headers_b).status_code == 200
        assert client.get(f"/api/v1/attack-paths/{FOREIGN}", headers=headers_a).status_code == 404

    def test_a_foreign_path_and_a_missing_path_are_indistinguishable(
        self, client, headers_a
    ) -> None:
        # Any difference between these two responses is an oracle for
        # enumerating another tenant's attack paths.
        foreign = client.get(f"/api/v1/attack-paths/{FOREIGN}", headers=headers_a)
        absent = client.get("/api/v1/attack-paths/no-such-path-at-all", headers=headers_a)

        assert foreign.status_code == absent.status_code == 404
        # Everything but the per-request correlation id, which is
        # deliberately unique and carries no information about the path.
        for envelope in ("code", "message", "details"):
            assert foreign.json()["error"][envelope] == absent.json()["error"][envelope]

    def test_the_scan_scoped_list_does_not_leak_across_tenants(
        self, client, headers_a, headers_b
    ) -> None:
        # Both tenants scanned under the SAME scan key in this fixture,
        # which is the arrangement a scan_key-only WHERE clause fails.
        a = client.get(LIST, headers=headers_a).json()
        b = client.get(LIST, headers=headers_b).json()
        assert {i["id"] for i in a["items"]}.isdisjoint({i["id"] for i in b["items"]})
