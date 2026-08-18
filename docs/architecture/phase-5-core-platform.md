# Phase 5 — Core Platform & Data Service

> Verified by execution. Test counts and gate output are real output from
> this repository. Where something was not verified, it says so.

Phase 4 made scan history durable. Phase 5 makes it **reachable** — by
the AI Service, by a future dashboard, by anything with a token — while
keeping Core the authoritative owner of what is true.

---

## 1. The invariant

```
                    AUTHORITATIVE DATA
                           │
                      CORE SERVICE
                      /          \
                     ▼            ▼
                AI SERVICE     DASHBOARD
              (reasoning)    (presentation)
```

Core owns findings, resources, scans and scores. The AI Service reasons
over them and never becomes their owner. The dashboard presents them and
must keep working when the AI Service is down — which it does, because
nothing in this API depends on the AI Service existing.

---

## 2. What Phase 5 added

| Layer | Added |
|---|---|
| Domain | `compliance/scoring.py` (ComplianceScore), `audit/models.py` (AuditEvent) |
| Application | ports: auth, system, jobs, queries, audit · use cases: finding pages, scores, scan submission |
| Infrastructure | RS256 JWT + JWKS, in-memory + Postgres query repositories, system adapters |
| Presentation | FastAPI app, schemas, dependencies, errors, middleware, 4 routers |
| Persistence | `compliance_scores`, `audit_events`, migration 0002 |
| Root | `composition.py`, `Dockerfile`, `docker-compose.yml`, `.env.example` |

Phases 1–4 were **not redesigned**. The only pre-existing file changed
was `pyproject.toml`, to declare Phase 4's undeclared sqlalchemy/psycopg/
alembic dependencies — a real defect that made `pip install .` produce a
package unable to import its own persistence layer.

---

## 3. Layering

```
presentation/   FastAPI, Pydantic          ← may import application, domain
     ↓
application/    use cases + PORTS          ← may import domain only
     ↓
domain/         entities, policies         ← imports nothing
     ↑
infrastructure/ SQLAlchemy, psycopg, JWT   ← implements ports
```

Asserted from the AST, not by convention
(`tests/api/test_architecture.py`):

- domain imports no framework, no infrastructure, no application
- application imports no FastAPI, no SQLAlchemy, no infrastructure
- presentation imports no database driver and no infrastructure
- **exactly one module imports `jwt`** — two implementations of token
  verification would disagree eventually, and that is how a service ends
  up with one path that checks the audience and one that does not
- **no route handler declares a `tenant_id` parameter** — if one existed,
  a caller could supply it and the security boundary would become an
  argument

### Deviation from the brief's §4 layout

The brief specifies `src/complianceiq/domain/entities/…`. This repository
keeps its flat `domain/ application/ infrastructure/` tree and adds
`presentation/` alongside, because §39 also says not to rewrite working
architecture: adopting the nested layout would rewrite imports across
293 files, the Alembic module path and the packaging config, for zero
functional change. The rule §4 exists to enforce is a property of the
dependency graph, and that property is now machine-checked.

---

## 4. Endpoint matrix

| Method | Path | Role | Success | Errors |
|---|---|---|---|---|
| GET | `/api/v1/findings` | reader | 200 `Page<Finding>` | 401 403 422 |
| GET | `/api/v1/findings/ai-contract` | reader | 200 `Page<AiFindingContract>` | 401 403 422 |
| GET | `/api/v1/findings/{id}` | reader | 200 `Finding` | 401 403 404 |
| GET | `/api/v1/findings/{id}/ai-contract` | reader | 200 `AiFindingContract` | 401 403 404 409 |
| GET | `/api/v1/scores` | reader | 200 `Page<ComplianceScore>` | 401 403 422 |
| GET | `/api/v1/scores/current` | reader | 200 `ComplianceScore` | 401 403 404 |
| POST | `/api/v1/scans` | **scanner** | 202 `ScanSubmission` | 401 403 409 422 503 |
| GET | `/api/v1/scans` | reader | 200 `ScanResource[]` | 401 403 |
| GET | `/api/v1/scans/{scan_key}` | reader | 200 `ScanResource` | 401 403 404 |
| GET | `/health` | — | 200 / 503 | — |
| GET | `/version` | — | 200 | — |
| GET | `/.well-known/jwks.json` | — | 200 | — |

---

## 5. Multi-tenancy

Four independent layers, each of which alone would be a single point of
failure:

1. **The token.** `tenant_id` comes from the verified JWT. There is no
   tenant parameter anywhere in the API surface.
2. **The type.** `AuthenticatedIdentity` is constructible only by a
   `TokenVerifier`, so holding one is proof a signature was checked.
3. **The port.** Every repository method requires `tenant_id`. A method
   that cannot be called without naming a tenant cannot accidentally
   return another tenant's rows.
4. **The query.** Every `SELECT` filters on it, including those already
   filtering on a unique primary key — redundant today, uniform in
   review.

### 404, not 403

A finding belonging to another tenant returns **exactly** the response a
non-existent one returns: same status, same code, same message. If they
differed at all, the difference would be an oracle for enumerating other
tenants' finding ids — an information leak even though the data is never
returned. Tested by asserting the two responses are byte-identical.

---

## 6. Authentication

RS256, not HS256. With a shared secret, every service that verifies a
token can also mint one — the AI Service would hold a credential letting
it impersonate any tenant. With RS256 the private key never leaves Core.

`algorithms=["RS256"]` is passed explicitly to `jwt.decode`. Without it,
a token with `"alg": "none"`, or one signed with HS256 using the *public*
key as the HMAC secret, verifies successfully. Both attacks are tested;
the HS256 one is forged by hand because PyJWT's encoder refuses to
produce it, and testing the library's politeness would not test our
verifier.

`tenant_id` is required and never defaulted — a default tenant is a
cross-tenant read waiting to happen.

An unrecognized role in a token is ignored rather than fatal: a newer
issuer may mint roles this deployment does not know, and failing closed
on the whole token would break rollout. Ignoring is safe because an
unknown role grants nothing.

### Deviation: issuance scope

§13 requires Core to issue tokens, but the repository has no user entity,
no credential store, and §36 never asks for a login flow. Phase 5
implements the **service-to-service** reading — issuance for configured
clients plus JWKS publication — and invents no user table, password
hashing or login endpoint.

---

## 7. Scoring

`ComplianceScore` is the one genuinely new domain concept. Phase 4 had a
score as a *property* on one read model covering one scope; the API needs
tenant, framework, domain and scan scopes.

Two properties matter more than the arithmetic:

**Deterministic.** No clock, no randomness. Same findings, same score.
An auditor recomputing last quarter must get last quarter's number.

**No hidden compliance.** INDETERMINATE is excluded from the denominator,
never counted as a pass, and a scope with nothing determinate scores
`null` rather than a misleading 100%. `coverage` sits next to `score` to
make "100% over 4 of 900 checks" visible as the absent posture it is.

Scores are computed once when a scan completes, not at read time.
Scoring on read would re-aggregate every finding per page load, and the
number would drift as history was appended — last quarter's score would
silently change.

---

## 8. Scan lifecycle

`POST /scans` → **202** with an id and a status, never results.

Sequencing: persist the scan as QUEUED in its own transaction, **then**
submit the job, then return. The reverse order has a window where the job
starts, does real work, and nothing in the database knows — so a crash
leaves no trace of a scan that touched production infrastructure.

Phase 4's six states are kept as-is. The brief's §26 pipeline lists
`collecting/normalizing/evaluating/scoring`, but those are phases *within*
RUNNING, not peers of it; promoting them to top-level states would break
the tested state machine and its CHECK constraints. `PARTIAL` is absent
from §26's list and is retained deliberately — it is what distinguishes
"scanned everything" from "was denied KMS", and reporting the latter as
COMPLETED tells an auditor that KMS was checked and found compliant.

`ScanWorker` guarantees every exit path leaves the scan terminal. A
worker that raised and left a scan RUNNING forever would be worse than
one that failed loudly.

---

## 9. Error contract

One envelope for every error, including validation errors and 500s and
errors raised inside FastAPI before our code runs. An API that returns
its own shape for expected errors and FastAPI's `{"detail": …}` for
everything else has two contracts, and the second one is undocumented.

Unexpected exceptions return a fixed string; the detail goes to the log,
keyed by correlation id, where an operator can find it and an attacker
cannot. Tested by making a use case raise an exception containing a
connection string and asserting the credential does not reach the client.

401 never says which check failed. Distinguishing expired from
bad-signature from wrong-audience is free reconnaissance.

---

## 10. Testing

| Suite | Count | Needs |
|---|---|---|
| Full suite | **1022 passed**, 60 skipped | — |
| API (contract + security + architecture) | 99 | nothing |
| Phase 5 Postgres repositories | 25 | a real database |
| Phase 4 persistence + migrations | 72 | a real database |
| Part 20 security (database-free) | 46 | nothing |

The 60 skips are Phase 3's AWS/Azure cloud tests, which need real cloud
credentials. Reported as skipped, never as passed.

The API tests run over in-memory repositories but through the **real**
`create_app` — real routing, auth, tenant scoping, serialization and
error handling. Whether PostgreSQL honours the same semantics is a
separate question answered by the real-database suite, which is why both
exist.

### Gates

```
$ python3 -m pytest -q
1022 passed, 60 skipped in 24.87s

$ ruff check .
All checks passed!

$ mypy domain application infrastructure contracts presentation composition.py
Success: no issues found in 164 source files

$ alembic upgrade head
Running upgrade 0001 -> 0002, Compliance scores and audit events (Phase 5).
```

---

## 11. Known gaps

Stated rather than hidden:

- **GCP is not implemented.** `provider` accepts `aws` and `azure`; `gcp`
  is a 422. The connector seam is provider-neutral, so adding it needs no
  redesign — but it is a body of work comparable to Azure and orthogonal
  to this phase.
- **`build_production_app` uses one long-lived session** for the read
  repositories. A per-request session scope is correct and needs a
  request-scoped dependency; this is the most significant remaining gap.
- **Scan submission returns 503** in the default production profile until
  a cloud credentials reference and rule catalog path are configured. The
  pipeline is implemented and tested; its configuration is
  deployment-specific.
- **No rate limiting.** §28 asks for a strategy; none is implemented.
- **No token revocation.** Expiry is the only revocation mechanism.
- **Docker images were not built** — no Docker daemon in this
  environment. The Dockerfile and compose file are written and reviewed,
  not executed.
- **No load testing.** Pagination and indexes are correct by
  construction and tested for correctness, not measured under volume.

---

## Related

- [Phase 5 audit](phase-5-audit.md) — the gap analysis and the six conflicts
- [AI Service integration](../integration/ai-service-integration.md) — the client-facing contract
- [Phase 5 implementation report](phase-5-implementation-report.md) — PASS/FAIL
- [Phase 4 persistence](phase-4-persistence.md)
