"""Contract tests for AI Service consumption (§14, §15, §30).

The AI Service is being built by another engineer against this API. That
makes these tests unusual in purpose: they are not checking that our code
works, they are **pinning the contract** so that a future refactor which
still passes every other test but changes a field name, a status code, or
the error envelope fails loudly here.

If a test in this file fails, the correct reaction is usually not "fix
the test" — it is "you just broke the AI Service; either revert it or
ship /api/v2".
"""

from __future__ import annotations

import pytest

from tests.api.conftest import TENANT_A


class TestPageContract:
    """§6: `{items, total, limit, offset}` — identical on every list."""

    @pytest.mark.parametrize("path", ["/api/v1/findings", "/api/v1/scores"])
    def test_page_envelope_shape(self, client, auth_headers, path) -> None:
        body = client.get(path, headers=auth_headers).json()
        assert set(body) == {"items", "total", "limit", "offset", "has_more"}
        assert isinstance(body["items"], list)
        assert isinstance(body["total"], int)

    def test_default_limit_is_50(self, client, auth_headers) -> None:
        assert client.get("/api/v1/findings", headers=auth_headers).json()["limit"] == 50

    def test_limit_above_the_maximum_is_rejected(self, client, auth_headers) -> None:
        # Not silently clamped: a client asking for 1000 should learn
        # that it cannot have it, rather than believing it received
        # everything when it received 100.
        response = client.get("/api/v1/findings?limit=101", headers=auth_headers)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"

    def test_zero_and_negative_bounds_are_rejected(self, client, auth_headers) -> None:
        assert client.get("/api/v1/findings?limit=0", headers=auth_headers).status_code == 422
        assert client.get("/api/v1/findings?offset=-1", headers=auth_headers).status_code == 422

    def test_pagination_is_stable_and_non_overlapping(self, client, auth_headers) -> None:
        # The unstable-pagination bug: without a unique tiebreaker, rows
        # with equal timestamps can appear on two pages or none. Every
        # fixture finding shares `detected_at`, so this would fail
        # immediately if the tiebreaker were missing.
        first = client.get("/api/v1/findings?limit=2&offset=0", headers=auth_headers).json()
        second = client.get("/api/v1/findings?limit=2&offset=2", headers=auth_headers).json()

        ids_first = [i["id"] for i in first["items"]]
        ids_second = [i["id"] for i in second["items"]]
        assert len(set(ids_first) & set(ids_second)) == 0
        assert first["total"] == second["total"] == 4

    def test_repeating_the_same_query_returns_the_same_order(
        self, client, auth_headers
    ) -> None:
        a = client.get("/api/v1/findings", headers=auth_headers).json()
        b = client.get("/api/v1/findings", headers=auth_headers).json()
        assert [i["id"] for i in a["items"]] == [i["id"] for i in b["items"]]

    def test_an_empty_result_is_a_valid_page_not_a_404(self, client, auth_headers) -> None:
        body = client.get(
            "/api/v1/findings?rule_id=no-such-rule", headers=auth_headers
        ).json()
        assert body["items"] == []
        assert body["total"] == 0


class TestFindingContract:
    """§7: the finding fields the AI Service and dashboard consume."""

    REQUIRED = {
        "id",
        "tenant_id",
        "resource_id",
        "rule_id",
        "framework",
        "control_id",
        "domain",
        "status",
        "severity",
        "evidence",
        "detected_at",
    }

    def test_every_required_field_is_present(self, client, auth_headers) -> None:
        item = client.get("/api/v1/findings", headers=auth_headers).json()["items"][0]
        assert self.REQUIRED <= set(item)

    def test_indeterminate_findings_are_returned_not_hidden(
        self, client, auth_headers
    ) -> None:
        # The no-hidden-compliance rule at the API boundary. Omitting
        # these would make an unevaluated check look like a pass.
        body = client.get(
            "/api/v1/findings?status=indeterminate", headers=auth_headers
        ).json()
        assert body["total"] == 1
        assert body["items"][0]["status"] == "indeterminate"

    def test_status_is_three_valued(self, client, auth_headers) -> None:
        body = client.get("/api/v1/findings", headers=auth_headers).json()
        assert {i["status"] for i in body["items"]} == {"fail", "pass", "indeterminate"}

    def test_detected_at_is_iso8601_with_timezone(self, client, auth_headers) -> None:
        item = client.get("/api/v1/findings", headers=auth_headers).json()["items"][0]
        # A naive timestamp is ambiguous across deployments; the domain
        # rejects one, and it must not become naive on the wire either.
        assert item["detected_at"].endswith("Z") or "+" in item["detected_at"]

    def test_logical_finding_id_is_exposed_for_cross_scan_history(
        self, client, auth_headers
    ) -> None:
        item = client.get("/api/v1/findings", headers=auth_headers).json()["items"][0]
        assert item["logical_finding_id"]
        assert item["logical_finding_id"] != item["id"], "physical vs logical identity"


class TestAiProjection:
    """The frozen 11-field Core↔AI contract (audit conflict C2)."""

    ELEVEN = {
        "id",
        "tenant_id",
        "resource_id",
        "rule_id",
        "framework",
        "control_id",
        "domain",
        "status",
        "severity",
        "evidence",
        "detected_at",
    }

    def test_ai_view_returns_exactly_eleven_fields(self, client, auth_headers) -> None:
        body = client.get("/api/v1/findings/ai-contract", headers=auth_headers).json()
        assert body["items"], "expected at least one representable finding"
        for item in body["items"]:
            assert set(item) == self.ELEVEN, "the AI Service rejects unknown fields"

    def test_ai_view_omits_indeterminate_findings(self, client, auth_headers) -> None:
        # The AI contract's status enum has two values; an INDETERMINATE
        # finding cannot be represented and is skipped rather than
        # coerced into a verdict it does not have.
        body = client.get("/api/v1/findings/ai-contract", headers=auth_headers).json()
        assert all(i["status"] in ("pass", "fail") for i in body["items"])

    def test_single_finding_ai_contract_endpoint(
        self, client, auth_headers, findings_repo
    ) -> None:
        finding = next(
            f
            for f in findings_repo._findings
            if f.tenant_id == TENANT_A and f.status.value == "fail"
        )
        response = client.get(
            f"/api/v1/findings/{finding.id!s}/ai-contract", headers=auth_headers
        )
        assert response.status_code == 200
        assert set(response.json()) == self.ELEVEN

    def test_ai_contract_endpoint_refuses_an_indeterminate_finding(
        self, client, auth_headers, findings_repo
    ) -> None:
        finding = next(
            f
            for f in findings_repo._findings
            if f.tenant_id == TENANT_A and f.status.value == "indeterminate"
        )
        response = client.get(
            f"/api/v1/findings/{finding.id!s}/ai-contract", headers=auth_headers
        )
        # 409, not 500 and not a silent coercion.
        assert response.status_code == 409

    def test_the_full_view_is_a_superset_of_the_ai_view(
        self, client, auth_headers
    ) -> None:
        full = client.get("/api/v1/findings", headers=auth_headers).json()["items"][0]
        assert self.ELEVEN <= set(full)


class TestFilterContract:
    @pytest.mark.parametrize(
        "query,expected",
        [
            ("severity=critical", 1),
            ("severity=high", 1),
            ("status=fail", 2),
            ("status=pass", 1),
            ("domain=storage", 3),
            ("domain=encryption", 1),
            ("framework=iso_27001", 4),
            ("resource_id=bucket-1", 1),
        ],
    )
    def test_filters_narrow_results(self, client, auth_headers, query, expected) -> None:
        body = client.get(f"/api/v1/findings?{query}", headers=auth_headers).json()
        assert body["total"] == expected

    @pytest.mark.parametrize(
        "query",
        ["severity=catastrophic", "status=maybe", "provider=oracle", "sort=random"],
    )
    def test_unknown_enum_values_are_rejected(self, client, auth_headers, query) -> None:
        # Closed vocabularies, validated before any query runs.
        response = client.get(f"/api/v1/findings?{query}", headers=auth_headers)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_error"

    def test_combined_filters_intersect(self, client, auth_headers) -> None:
        body = client.get(
            "/api/v1/findings?status=fail&severity=critical", headers=auth_headers
        ).json()
        assert body["total"] == 1


class TestErrorEnvelope:
    """§17: one shape for every error."""

    def _assert_envelope(self, payload: dict) -> None:
        assert set(payload) == {"error"}
        error = payload["error"]
        assert set(error) == {"code", "message", "correlation_id", "details"}
        assert isinstance(error["code"], str) and error["code"]
        assert isinstance(error["message"], str) and error["message"]
        assert isinstance(error["correlation_id"], str) and error["correlation_id"]
        assert isinstance(error["details"], dict)

    def test_401_uses_the_envelope(self, client) -> None:
        self._assert_envelope(client.get("/api/v1/findings").json())

    def test_403_uses_the_envelope(self, client, auth_headers) -> None:
        response = client.post("/api/v1/scans", headers=auth_headers, json={"provider": "aws"})
        self._assert_envelope(response.json())

    def test_404_uses_the_envelope(self, client, auth_headers) -> None:
        self._assert_envelope(client.get("/api/v1/findings/nope", headers=auth_headers).json())

    def test_422_uses_the_envelope(self, client, auth_headers) -> None:
        self._assert_envelope(client.get("/api/v1/findings?limit=999", headers=auth_headers).json())

    def test_unmatched_route_uses_the_envelope(self, client) -> None:
        # FastAPI's built-in 404 would otherwise return {"detail": ...},
        # a second undocumented error shape.
        self._assert_envelope(client.get("/api/v1/does-not-exist").json())

    def test_405_uses_the_envelope(self, client, auth_headers) -> None:
        self._assert_envelope(client.delete("/api/v1/findings", headers=auth_headers).json())


class TestCorrelationId:
    """§16: preserve if supplied, generate if not, always return it."""

    def test_a_supplied_id_is_preserved(self, client, auth_headers) -> None:
        response = client.get(
            "/api/v1/findings",
            headers={**auth_headers, "X-Correlation-ID": "trace-abc-123"},
        )
        assert response.headers["X-Correlation-ID"] == "trace-abc-123"

    def test_one_is_generated_when_absent(self, client, auth_headers) -> None:
        response = client.get("/api/v1/findings", headers=auth_headers)
        assert response.headers["X-Correlation-ID"]

    def test_generated_ids_differ_between_requests(self, client, auth_headers) -> None:
        a = client.get("/api/v1/findings", headers=auth_headers)
        b = client.get("/api/v1/findings", headers=auth_headers)
        assert a.headers["X-Correlation-ID"] != b.headers["X-Correlation-ID"]

    def test_it_appears_in_the_error_body_and_header(self, client) -> None:
        response = client.get(
            "/api/v1/findings", headers={"X-Correlation-ID": "trace-err-1"}
        )
        assert response.headers["X-Correlation-ID"] == "trace-err-1"
        assert response.json()["error"]["correlation_id"] == "trace-err-1"

    def test_a_hostile_correlation_id_is_replaced(self, client, auth_headers) -> None:
        # Caller-controlled text that lands in every log line for the
        # request. A newline could forge a log record.
        response = client.get(
            "/api/v1/findings",
            headers={**auth_headers, "X-Correlation-ID": "abc\ndef"},
        )
        assert "\n" not in response.headers["X-Correlation-ID"]
        assert response.headers["X-Correlation-ID"] != "abc\ndef"

    def test_an_overlong_correlation_id_is_replaced(self, client, auth_headers) -> None:
        response = client.get(
            "/api/v1/findings", headers={**auth_headers, "X-Correlation-ID": "x" * 500}
        )
        assert len(response.headers["X-Correlation-ID"]) < 200


class TestScanContract:
    """§26: job-oriented, never implying synchronous completion."""

    def test_submitting_returns_202_with_an_id_and_status(
        self, client, scanner_headers
    ) -> None:
        response = client.post(
            "/api/v1/scans", headers=scanner_headers, json={"provider": "aws"}
        )
        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "queued"
        assert body["scan_key"]

    def test_the_submission_response_contains_no_results(
        self, client, scanner_headers
    ) -> None:
        # Returning findings here would imply the scan had finished.
        body = client.post(
            "/api/v1/scans", headers=scanner_headers, json={"provider": "aws"}
        ).json()
        assert "findings" not in body
        assert "resources" not in body

    def test_a_client_supplied_tenant_id_is_rejected(self, client, scanner_headers) -> None:
        # extra="forbid" turns a mass-assignment attempt into a 422
        # instead of a silently ignored field.
        response = client.post(
            "/api/v1/scans",
            headers=scanner_headers,
            json={"provider": "aws", "tenant_id": "globex"},
        )
        assert response.status_code == 422

    def test_an_unknown_provider_is_rejected(self, client, scanner_headers) -> None:
        response = client.post(
            "/api/v1/scans", headers=scanner_headers, json={"provider": "gcp"}
        )
        assert response.status_code == 422

    def test_a_duplicate_submission_conflicts(self, client, scanner_headers, app) -> None:
        app.state.scan_stub.conflict = True
        response = client.post(
            "/api/v1/scans", headers=scanner_headers, json={"provider": "aws"}
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "scan_conflict"

    def test_an_unknown_scan_is_404(self, client, auth_headers) -> None:
        assert client.get("/api/v1/scans/nope", headers=auth_headers).status_code == 404


class TestMetaEndpoints:
    def test_health_is_public(self, client) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_version_reports_the_api_version(self, client) -> None:
        assert client.get("/version").json()["api_version"] == "v1"

    def test_jwks_is_public_and_well_formed(self, client) -> None:
        body = client.get("/.well-known/jwks.json").json()
        assert body["keys"][0]["kty"] == "RSA"
        assert body["keys"][0]["alg"] == "RS256"
