# Phase 5 — Implementation Report

> **Verification policy.** Every PASS below was produced by executing a
> command and reading its real output. Nothing is PASS because the code
> was written. Where something could not be executed here it is marked
> **NOT VERIFIED** with the reason, and where a requirement was
> deliberately not met it is marked **DEVIATION** with the rationale —
> never quietly as PASS.

- **Phase:** 5 — Core Platform & Data Service
- **Date:** 2026-08-13
- **Database:** PostgreSQL **16.13** (real server)
- **Audit:** [phase-5-audit.md](phase-5-audit.md) · **Design:** [phase-5-core-platform.md](phase-5-core-platform.md)
- **AI contract:** [ai-service-integration.md](../integration/ai-service-integration.md)

---

## 1. Definition of Done (§36)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Core architecture is clean | **PASS** | AST layering tests; mypy clean, 164 files |
| 2 | Cloud connectors work behind ports | **PASS** | `BaseCollector` unchanged from Phase 3; AWS + Azure |
| 3 | Normalization is provider-neutral | **PASS** | `NormalizedResource`; no SDK type reaches domain |
| 4 | Rule engine produces valid Findings | **PASS** | Phase 3 engine unchanged; 1022 tests green |
| 5 | Scores are deterministic | **PASS** | §3.3 — no clock/randomness; property-tested |
| 6 | Findings are persisted | **PASS** | Phase 4 tables + 72 real-DB tests |
| 7 | Scans are first-class jobs | **PASS** | 202 + poll; `ScanJobRunner` port |
| 8 | REST API is versioned | **PASS** | `/api/v1`; ops endpoints outside it |
| 9 | JWT authentication works | **PASS** | 30 security tests |
| 10 | JWT issuance works | **PASS** | `JwtTokenIssuer`; RS256 round trip |
| 11 | Public key distributable to AI | **PASS** | `/.well-known/jwks.json`, public numbers only |
| 12 | Tenant isolation enforced | **PASS** | §3.1 — 4 layers, adversarially tested |
| 13 | Filtering works | **PASS** | Typed closed vocabularies; 422 on unknown |
| 14 | Pagination works | **PASS** | Bounded, deterministic, stable across pages |
| 15 | Error envelope is consistent | **PASS** | Every path incl. 404/405/500 |
| 16 | Correlation IDs work | **PASS** | Preserve/generate/echo + sanitization |
| 17 | OpenAPI is complete | **PASS** | 11 paths, 21 schemas; 11 spec tests |
| 18 | AI contract tests pass | **PASS** | 82 contract tests + 14 fixtures |
| 19 | Dashboard-independent backend | **PASS** | No dashboard code; no AI dependency |
| 20 | Audit trail exists | **PASS** | `AuditEvent`, `audit_events`, append-only |
| 21 | Security tests pass | **PASS** | 76 security tests |
| 22 | Unit tests pass | **PASS** | 1022 passed |
| 23 | Integration tests pass | **PASS** | 72 against real PostgreSQL |
| 24 | Contract tests pass | **PASS** | 99 API tests |
| 25 | Architecture tests pass | **PASS** | Layering + OpenAPI, AST-based |
| 26 | Documentation complete | **PASS** | 6 architecture + 5 contract + 1 integration |
| 27 | No secrets committed | **PASS** | §3.4 |
| 28 | No cross-layer violations | **PASS** | §3.2 |

**28 PASS · 0 FAIL.** Plus four deviations and five not-verified items,
below — those are *not* counted as passes.

---

## 2. Gates — executed

```
$ python3 -m pytest -q
1022 passed, 60 skipped in 23.89s

$ python3 -m pytest tests/api -q
99 passed

$ python3 -m pytest tests/integration/persistence -q
72 passed

$ ruff check .
All checks passed!

$ mypy domain application infrastructure contracts presentation composition.py
Success: no issues found in 164 source files

$ alembic upgrade head
Running upgrade 0001 -> 0002, Compliance scores and audit events (Phase 5).
```

The 60 skips are Phase 3's AWS/Azure cloud tests, which need real cloud
credentials. Reported as skipped, never as passed.

---

## 3. Evidence

### 3.1 Tenant isolation

Four independent layers (see [tenancy.md](tenancy.md)). Tested with two
tenants whose findings deliberately share resource ids and rules — a
single-tenant fixture cannot detect a missing filter, because every query
would return the right answer by accident.

The strongest assertion: a foreign finding and a non-existent one return
**byte-identical** responses — same status, same code, same message — so
ids cannot be probed.

### 3.2 Layering

AST-parsed, not grepped:

- domain imports no framework, no infrastructure, no application
- application imports no FastAPI, SQLAlchemy or infrastructure
- presentation imports no database driver or infrastructure module
- exactly **one** module imports `jwt`
- **no** route handler declares a `tenant_id` parameter

### 3.3 Deterministic scoring

No clock read, no randomness; counts are integers and the division
happens once. INDETERMINATE is excluded from the denominator, and a scope
with nothing determinate returns `null`, not 100%.

### 3.4 Secrets

- `.env` gitignored; `.env.example` carries names only
- `JWT_PRIVATE_KEY` from environment, **no generate-at-boot fallback** —
  a boot-generated key would differ per replica, so instances behind a
  load balancer would reject each other's tokens
- `IssuedToken.__repr__` and `RsaKeyPair.__repr__` withhold material
- JWKS exposes only `n`/`e`; a test asserts no `d`/`p`/`q`/`dp`/`dq`/`qi`
- Dockerfile bakes in no secret; runs as UID 10001, non-root
- A 500 whose underlying exception contained a connection string returns
  a fixed message — tested by asserting the credential does not appear

### 3.5 Defects found by tests, not review

| Defect | Consequence | Found by |
|---|---|---|
| `response_model` coerced the AI projection to the full schema | AI clients would receive 17 fields and reject the response | contract test |
| `metadata=` in an insert resolves to SQLAlchemy's `MetaData` | Audit writes failed with an unrelated-looking `AttributeError` | real-DB test |
| Migration test hardcoded head `"0001"` | Every future migration breaks it for no reason | full run after 0002 |
| `pyproject` declared no sqlalchemy/psycopg/alembic | `pip install .` produced a package unable to import its own persistence | audit |

The first also produced a design improvement: a query parameter that
changes a *response schema* makes the OpenAPI document ambiguous, so the
AI projection became its own path.

---

## 4. Deviations from the brief — stated, not hidden

| § | Requirement | What was done | Why |
|---|---|---|---|
| §4 | `src/complianceiq/` layout | Kept flat tree, added `presentation/` | §39 forbids rewriting working architecture; the move touches 293 files, the Alembic module path and packaging for zero functional change. The layering rule §4 protects is now machine-checked. |
| §7 | Extend `Finding` with ~11 fields | Richer REST schema; AI contract untouched | The AI contract is frozen at 11 fields and its consumer rejects extras. Extending breaks the service being built now; adopting it wholesale hides INDETERMINATE findings. Two projections, one ACL. |
| §4/§9 | GCP connector | Not implemented; `provider=gcp` → 422 | Comparable in size to the whole Azure effort (8 items) and orthogonal to the API/auth/scoring this phase is about. The seam is provider-neutral, so adding it needs no redesign. |
| §13 | Core issues JWTs | Service-to-service issuance + JWKS | No user entity, credential store or login flow exists, and §36 never asks for one. No user table was invented. |

Each was raised as a blocking question before implementation. No answer
was returned, so the documented recommendation was followed — in every
case the option that preserves the working system.

---

## 5. Not verified — stated plainly

| Item | Why | What would verify it |
|---|---|---|
| Docker image build | No Docker daemon in this sandbox (`/var/run/docker.sock` absent). Dockerfile and compose written and reviewed, **not built or run**. | `docker compose build` on a host with a daemon |
| `terraform validate` | Sandbox egress returns 403 from `registry.terraform.io`. Unchanged from Phase 3; Phase 5 did not touch Terraform. | `terraform init && validate` with registry access |
| Production performance | Paging and indexes are correct by construction and tested for correctness, not measured. No `EXPLAIN` under volume. | Load testing at representative volume |
| Concurrent scan submission | Deterministic keys + `ON CONFLICT` should make it safe; not measured. | A concurrency test with parallel writers |
| Rate limiting | §28 asks for a strategy; none implemented. | — |

None of these is marked PASS anywhere.

---

## 6. Known gaps in shipped code

- **`build_production_app` uses one long-lived session** for the
  read-side repositories. A per-request session scope is correct and
  needs a request-scoped dependency. This is the most significant
  remaining gap and is flagged in the code itself.
- **Scan submission returns 503** in the default production profile until
  a cloud credentials reference and rule catalog path are configured. The
  pipeline is implemented and tested; its configuration is
  deployment-specific. Deliberate and visible, not an oversight.
- **No reaper for stale RUNNING scans** after a process restart.
- **No token revocation** — expiry is the only mechanism, so lifetimes
  are capped at 24h.

---

## 7. Files created

**Domain (2):** `compliance/scoring.py`, `audit/models.py`

**Application (7):** `ports/auth.py`, `ports/system.py`, `ports/jobs.py`,
`ports/queries.py`, `ports/audit.py`, `findings/query_finding_pages.py`,
`compliance/query_scores.py`, `scanning/submit_scan.py`

**Infrastructure (4):** `auth/jwt_tokens.py`, `system/adapters.py`,
`persistence/memory/repositories.py`,
`persistence/postgres/repositories/api_repositories.py`

**Presentation (9):** `app.py`, `schemas.py`, `dependencies.py`,
`errors.py`, `middleware.py`, `routers/{findings,scores,scans,meta}.py`

**Persistence (2):** two tables in `models/tables.py`, migration `0002`

**Root (4):** `composition.py`, `Dockerfile`, `docker-compose.yml`,
`.env.example`

**Tests (4 files, 124 tests):** `tests/api/{conftest,test_security,
test_contracts,test_architecture}.py`,
`tests/integration/persistence/test_api_repositories.py`

**Fixtures (14):** `tests/contracts/fixtures/*.json`, all generated from
live responses

**Docs (12):** 6 architecture, 5 contract, 1 integration

**Modified (2):** `pyproject.toml` (dependency defect fix + `presentation`
package), `tests/integration/persistence/test_migrations.py` (derive head,
add the two new tables)

Phases 1–4 source was otherwise **not modified**.

---

## 8. Still unpushed

All Phase 5 work is committed locally on
`claude/complianceiq-phase-1-domain-hdsj3c`. It has **not** been pushed:
`git push` returns HTTP 403 (read-only credentials), and a request to
attach the repository with push access was declined. The branch also
still carries the divergence described in the Phase 4 report §5, which is
a decision for the repository owner.
