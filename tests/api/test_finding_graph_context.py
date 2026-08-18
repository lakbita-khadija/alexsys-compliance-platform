"""STEP 6 — Finding ↔ Attack Path correlation and graph context.

Four fields were persisted from the moment their columns existed and
none of them reached a client. The dashboard could report *this bucket
is public* but not *this bucket sits at the end of a chain that starts on
the internet* — which is the difference between a housekeeping item and
an incident.

The tests that matter most here are not the "field is present" ones.
They are:

* the **round trip** — a finding names a path, that path resolves, and it
  names the finding back;
* the **asymmetry** — the two directions answer different questions, and
  a client that assumes they are inverses will be wrong. Pinned so the
  behaviour cannot drift into an accidental fixed point either way;
* the **page/detail split** — graph context is unbounded per resource, so
  a page must not carry it.
"""

from __future__ import annotations

import pytest

from tests.api.conftest import (
    FLAGSHIP_FINDING_ID as FINDING_ID,
    FLAGSHIP_PATH_ID as FLAGSHIP,
    TENANT_A,
    TENANT_B,
)


@pytest.fixture()
def headers_a(token_factory):
    return {"Authorization": f"Bearer {token_factory(tenant=TENANT_A)}"}


def detail(client, headers, finding_id=FINDING_ID):
    response = client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


class TestFindingNamesItsAttackPaths:
    def test_the_ids_are_exposed(self, client, headers_a) -> None:
        assert detail(client, headers_a)["related_attack_path_ids"] == [FLAGSHIP]

    def test_paths_are_referenced_not_embedded(self, client, headers_a) -> None:
        # A path carries its whole node and edge list. Embedding it would
        # duplicate the graph into every finding row that touches it.
        ids = detail(client, headers_a)["related_attack_path_ids"]
        assert all(isinstance(i, str) for i in ids)

    def test_a_finding_on_no_path_reports_an_empty_list(self, client, headers_a) -> None:
        # Not null, and not absent: "no attack paths" is a determinate
        # answer and should not need special-casing by a client.
        body = detail(
            client,
            headers_a,
            "acme:111111111111:bucket-2:s3-bucket-public:2026-06-01T12:00:00+00:00-b",
        )
        assert body["related_attack_path_ids"] == []

    def test_the_named_path_actually_resolves(self, client, headers_a) -> None:
        # The link is only worth anything if following it works. This is
        # the test that would have caught an id format mismatch between
        # the two subsystems.
        path_id = detail(client, headers_a)["related_attack_path_ids"][0]
        response = client.get(f"/api/v1/attack-paths/{path_id}", headers=headers_a)
        assert response.status_code == 200
        assert response.json()["id"] == path_id


class TestTheRoundTrip:
    def test_finding_to_path_to_finding_closes(self, client, headers_a) -> None:
        finding = detail(client, headers_a)
        path_id = finding["related_attack_path_ids"][0]
        path = client.get(f"/api/v1/attack-paths/{path_id}", headers=headers_a).json()

        # The failing finding is named by the path it is named by.
        assert finding["id"] in path["contributing_finding_ids"]

    def test_the_path_target_is_the_findings_resource(self, client, headers_a) -> None:
        finding = detail(client, headers_a)
        path = client.get(
            f"/api/v1/attack-paths/{finding['related_attack_path_ids'][0]}",
            headers=headers_a,
        ).json()
        assert finding["resource_id"] == path["target"]


class TestTheTwoDirectionsAreNotInverses:
    """The asymmetry is deliberate; a client must not assume otherwise.

    `related_attack_path_ids` answers *is my resource on this path* and
    is status-agnostic. `contributing_finding_ids` answers *which
    misconfigurations create this risk* and lists failures only. A
    passing finding on a path resource therefore appears in the first and
    not the second.

    Pinned because the tempting "fix" — making them mirror — would either
    attribute a passing check to an attack path, or hide the fact that a
    resource on a chain has other findings against it.
    """

    def test_the_documented_asymmetry_is_described_in_the_schema(self, client) -> None:
        spec = client.get("/openapi.json").json()
        description = spec["components"]["schemas"]["FindingResource"]["properties"][
            "related_attack_path_ids"
        ]["description"]
        # A client generating from the spec must be able to learn this
        # without reading our source.
        assert "not the inverse" in description.lower()

    def test_contributing_ids_are_a_subset_of_what_points_at_the_path(
        self, client, headers_a
    ) -> None:
        path = client.get(f"/api/v1/attack-paths/{FLAGSHIP}", headers=headers_a).json()
        for finding_id in path["contributing_finding_ids"]:
            body = client.get(f"/api/v1/findings/{finding_id}", headers=headers_a)
            assert body.status_code == 200
            assert FLAGSHIP in body.json()["related_attack_path_ids"]


class TestGraphContext:
    def test_the_detail_endpoint_returns_it(self, client, headers_a) -> None:
        context = detail(client, headers_a)["graph_context"]
        assert context is not None
        assert [e["relationship"] for e in context["outgoing"]] == ["accesses"]
        assert [e["relationship"] for e in context["incoming"]] == ["attached_to"]

    def test_edges_carry_their_evidence_and_confidence(self, client, headers_a) -> None:
        # Context without evidence is an assertion a responder cannot
        # check, which is the thing this project keeps refusing to ship.
        outgoing = detail(client, headers_a)["graph_context"]["outgoing"][0]
        assert outgoing["confidence"] == "high"
        assert outgoing["evidence"] == {"evidence_level": "exact"}

    def test_the_list_endpoint_omits_it(self, client, headers_a) -> None:
        # One security group can front hundreds of instances, so a page
        # carrying context would size responses by graph shape.
        page = client.get("/api/v1/findings", headers=headers_a).json()
        assert {item["graph_context"] for item in page["items"]} == {None}

    def test_the_list_still_carries_the_bounded_context(self, client, headers_a) -> None:
        # The distinction is size, not sensitivity: id lists are bounded
        # and stay in the page.
        item = next(
            i for i in client.get("/api/v1/findings", headers=headers_a).json()["items"]
            if i["id"] == FINDING_ID
        )
        assert item["related_attack_path_ids"] == [FLAGSHIP]
        assert item["related_resources"] == ["i-web", "sg-1"]

    def test_a_finding_without_context_returns_null(self, client, headers_a) -> None:
        body = detail(
            client,
            headers_a,
            "acme:111111111111:bucket-2:s3-bucket-public:2026-06-01T12:00:00+00:00-b",
        )
        assert body["graph_context"] is None


class TestIndeterminateResourcesStaySeparate:
    def test_they_are_not_merged_into_related_resources(self, client, headers_a) -> None:
        # The same principle as three-valued status: a neighbour we could
        # not evaluate must never be read back as a confirmed one.
        body = detail(client, headers_a)
        assert body["related_resources"] == ["i-web", "sg-1"]
        assert body["indeterminate_resources"] == ["kms-key-1"]
        assert "kms-key-1" not in body["related_resources"]


class TestTenantIsolation:
    def test_another_tenant_cannot_read_the_correlated_finding(
        self, client, token_factory
    ) -> None:
        headers_b = {"Authorization": f"Bearer {token_factory(tenant=TENANT_B)}"}
        assert client.get(f"/api/v1/findings/{FINDING_ID}", headers=headers_b).status_code == 404

    def test_a_foreign_tenant_cannot_pivot_through_a_path_id(
        self, client, token_factory
    ) -> None:
        # The pivot the new field enables is the one worth checking: even
        # holding a valid path id from a finding they cannot read, the
        # other tenant gets nothing.
        headers_b = {"Authorization": f"Bearer {token_factory(tenant=TENANT_B)}"}
        assert client.get(f"/api/v1/attack-paths/{FLAGSHIP}", headers=headers_b).status_code == 404

    def test_tenant_b_findings_carry_no_foreign_path_ids(
        self, client, token_factory
    ) -> None:
        headers_b = {"Authorization": f"Bearer {token_factory(tenant=TENANT_B)}"}
        page = client.get("/api/v1/findings", headers=headers_b).json()
        for item in page["items"]:
            assert all(pid.startswith("globex:") for pid in item["related_attack_path_ids"])


class TestBackwardCompatibility:
    def test_every_new_field_has_a_default(self, client) -> None:
        # Additive changes ship in v1. A required field would break every
        # existing generated client.
        schema = client.get("/openapi.json").json()["components"]["schemas"][
            "FindingResource"
        ]
        for field in (
            "related_attack_path_ids",
            "related_resources",
            "indeterminate_resources",
            "graph_context",
        ):
            assert field in schema["properties"]
            assert field not in schema.get("required", [])

    def test_the_ai_contract_is_unchanged(self, client, headers_a) -> None:
        # The frozen 11-field shape must not have grown. STEP 6 is a Core
        # dashboard concern; widening the AI contract would be a breaking
        # change to a different team's client.
        body = client.get(f"/api/v1/findings/{FINDING_ID}/ai-contract", headers=headers_a)
        assert body.status_code == 200
        assert len(body.json()) == 11
        assert "graph_context" not in body.json()
