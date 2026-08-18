"""Architecture and OpenAPI tests (§4, §21, §36).

Layering is asserted from the AST rather than trusted to review, for the
same reason Phase 4 asserted its own: a dependency rule that is only
written down is a rule that erodes one convenient import at a time.

The OpenAPI tests treat the spec as a **contract artifact**, not as
FastAPI's incidental output (§21). The AI engineer generates a client
from it, so a missing security scheme or an undocumented error shape is
a real defect — it produces a client that omits the Authorization header
and cannot parse failures.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _imports_of(path: pathlib.Path) -> set[str]:
    """Every module imported by a file, from its AST.

    AST rather than text search: a docstring that mentions SQLAlchemy
    while explaining why the layer avoids it must not fail the test, and
    an import nested inside a function must not escape it.
    """

    tree = ast.parse(path.read_text())
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _python_files(package: str) -> list[pathlib.Path]:
    return sorted((REPO_ROOT / package).rglob("*.py"))


class TestLayering:
    def test_domain_imports_no_framework_or_infrastructure(self) -> None:
        """The domain still knows nothing, after Phase 5."""

        forbidden = {
            "fastapi",
            "starlette",
            "pydantic",
            "jwt",
            "sqlalchemy",
            "psycopg",
            "alembic",
            "boto3",
            "infrastructure",
            "presentation",
            "application",
        }
        offenders = [
            f"{path.relative_to(REPO_ROOT)} imports {module}"
            for path in _python_files("domain")
            for module in _imports_of(path)
            if module.split(".")[0] in forbidden
        ]
        assert offenders == []

    def test_application_imports_no_framework_or_infrastructure(self) -> None:
        """Use cases depend on PORTS, never on adapters or HTTP.

        This is the test that would fail if someone typed a use case
        parameter as ``fastapi.Request`` or a repository as a SQLAlchemy
        ``Session`` — both tempting shortcuts.
        """

        forbidden = {
            "fastapi",
            "starlette",
            "pydantic",
            "jwt",
            "sqlalchemy",
            "psycopg",
            "alembic",
            "boto3",
            "infrastructure",
            "presentation",
        }
        offenders = [
            f"{path.relative_to(REPO_ROOT)} imports {module}"
            for path in _python_files("application")
            for module in _imports_of(path)
            if module.split(".")[0] in forbidden
        ]
        assert offenders == []

    def test_presentation_imports_no_infrastructure_or_driver(self) -> None:
        """Routers call use cases, never adapters (§4).

        Presentation may import FastAPI and Pydantic — that is its job —
        but reaching into ``infrastructure`` or a database driver would
        collapse the layering that makes the API testable without a
        database.
        """

        forbidden = {"sqlalchemy", "psycopg", "alembic", "boto3", "azure", "infrastructure"}
        offenders = [
            f"{path.relative_to(REPO_ROOT)} imports {module}"
            for path in _python_files("presentation")
            for module in _imports_of(path)
            if module.split(".")[0] in forbidden
        ]
        assert offenders == []

    def test_only_one_module_knows_what_a_jwt_is(self) -> None:
        """JWT handling is confined to its adapter.

        If a second module imported ``jwt``, token verification would
        have two implementations and they would disagree eventually —
        which is how a service ends up with one path that checks the
        audience and one that does not.
        """

        importers = {
            str(path.relative_to(REPO_ROOT))
            for package in ("domain", "application", "infrastructure", "presentation")
            for path in _python_files(package)
            if "jwt" in {m.split(".")[0] for m in _imports_of(path)}
        }
        assert importers == {"infrastructure/auth/jwt_tokens.py"}

    def test_tenant_id_is_never_read_from_a_request_parameter(self) -> None:
        """§12's central rule, enforced structurally.

        No route handler may declare a ``tenant_id`` parameter. If one
        existed, a caller could supply it, and the security boundary
        would become an argument.
        """

        offenders = []
        for path in _python_files("presentation"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = [a.arg for a in node.args.args + node.args.kwonlyargs]
                    if "tenant_id" in args:
                        offenders.append(f"{path.relative_to(REPO_ROOT)}::{node.name}")
        assert offenders == []


class TestOpenApiContract:
    @pytest.fixture()
    def spec(self, app) -> dict:
        return app.openapi()

    def test_the_spec_is_generated(self, spec) -> None:
        assert spec["openapi"].startswith("3.")
        assert spec["info"]["title"] == "ComplianceIQ Core API"

    def test_openapi_json_is_served(self, client) -> None:
        response = client.get("/openapi.json")
        assert response.status_code == 200
        assert "paths" in response.json()

    def test_docs_are_served(self, client) -> None:
        assert client.get("/docs").status_code == 200

    def test_every_documented_endpoint_exists(self, spec) -> None:
        expected = {
            "/api/v1/findings",
            "/api/v1/findings/{finding_id}",
            "/api/v1/findings/ai-contract",
            "/api/v1/findings/{finding_id}/ai-contract",
            "/api/v1/scores",
            "/api/v1/scores/current",
            "/api/v1/scans",
            "/api/v1/scans/{scan_key}",
            "/health",
            "/version",
            "/.well-known/jwks.json",
        }
        assert expected <= set(spec["paths"])

    def test_a_bearer_security_scheme_is_declared(self, spec) -> None:
        # Without this a generated client omits the Authorization header
        # entirely and 401s with no indication why.
        schemes = spec["components"]["securitySchemes"]
        assert schemes["bearerAuth"]["scheme"] == "bearer"
        assert schemes["bearerAuth"]["bearerFormat"] == "JWT"

    def test_every_v1_operation_requires_authentication(self, spec) -> None:
        unsecured = [
            f"{method.upper()} {path}"
            for path, operations in spec["paths"].items()
            if path.startswith("/api/v1")
            for method, operation in operations.items()
            if isinstance(operation, dict) and not operation.get("security")
        ]
        assert unsecured == []

    def test_operational_endpoints_are_not_marked_as_secured(self, spec) -> None:
        # A load balancer cannot present a JWT, and the AI Service must
        # be able to fetch JWKS before it holds a token.
        for path in ("/health", "/version", "/.well-known/jwks.json"):
            for operation in spec["paths"][path].values():
                if isinstance(operation, dict):
                    assert not operation.get("security")

    def test_error_responses_are_documented_with_the_envelope(self, spec) -> None:
        get_findings = spec["paths"]["/api/v1/findings"]["get"]
        for status_code in ("401", "403", "422"):
            assert status_code in get_findings["responses"], status_code

    def test_the_ai_contract_schema_has_exactly_eleven_fields(self, spec) -> None:
        # The frozen contract, asserted against the PUBLISHED spec — this
        # is what the AI engineer generates from.
        schema = spec["components"]["schemas"]["AiFindingContract"]
        assert len(schema["properties"]) == 11

    def test_enums_are_published_so_clients_can_generate_types(self, spec) -> None:
        schemas = spec["components"]["schemas"]
        finding = schemas["FindingResource"]["properties"]
        assert set(finding["status"]["enum"]) == {"fail", "pass", "indeterminate"}
        assert set(finding["severity"]["enum"]) == {"critical", "high", "medium", "low"}

    def test_pagination_parameters_document_their_bounds(self, spec) -> None:
        params = {
            p["name"]: p
            for p in spec["paths"]["/api/v1/findings"]["get"]["parameters"]
        }
        assert params["limit"]["schema"]["maximum"] == 100
        assert params["limit"]["schema"]["minimum"] == 1
        assert params["offset"]["schema"]["minimum"] == 0

    def test_no_endpoint_accepts_a_tenant_id_parameter(self, spec) -> None:
        # The OpenAPI-level restatement of the structural test above: the
        # published contract must not even suggest a tenant is selectable.
        offenders = []
        for path, operations in spec["paths"].items():
            for method, operation in operations.items():
                if not isinstance(operation, dict):
                    continue
                for param in operation.get("parameters", []):
                    if param.get("name") == "tenant_id":
                        offenders.append(f"{method.upper()} {path}")
        assert offenders == []
