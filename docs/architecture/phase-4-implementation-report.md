# Phase 4 — Implementation Report

> **Verification policy for this document.** Every PASS below was
> produced by executing a command in this environment and reading its
> real output. Nothing is marked PASS on the strength of having written
> the code. Where something could not be executed here, it is marked
> **NOT VERIFIED** and the reason is given — it is never marked PASS.

- **Phase:** 4 — PostgreSQL Persistence & Scan History
- **Date:** 2026-08-13
- **Database used for verification:** PostgreSQL **16.13** (real server,
  not a fake, not SQLite)
- **Design document:** [phase-4-persistence.md](phase-4-persistence.md)
- **Decision record:** [ADR-0001](../adr/ADR-0001-phase-4-postgresql-persistence.md)
- **Pre-implementation audit:** [phase-4-persistence-audit.md](phase-4-persistence-audit.md)

---

## 1. Summary

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | Audit before coding; no implementation started first | **PASS** | [audit doc](phase-4-persistence-audit.md), written and delivered before any Phase 4 code |
| 2 | PostgreSQL is the persistence technology | **PASS** | PostgreSQL 16.13; 47 tests executed against it |
| 3 | No MongoDB / SQLite / Redis / Elasticsearch introduced | **PASS** | §3.1 — dependency check |
| 4 | Persistence does not leak into Domain | **PASS** | §3.2 — AST scan of every `domain/` file: 0 violations |
| 5 | Phases 1–3 not redesigned; Phase 4 additive | **PASS** | §3.3 |
| 6 | Scan aggregate + state machine | **PASS** | `domain/scans/models.py`; 6 states, terminal states enforced |
| 7 | Finding lifecycle (open/resolved/reopened/suppressed) | **PASS** | `domain/scans/lifecycle.py`; Part 7 four-scan scenario tested |
| 8 | Repository ports defined in Application | **PASS** | 5 ports + `UnitOfWork`, all abstract |
| 9 | Explicit domain↔ORM mappers (no ORM leakage) | **PASS** | `mappers/mappers.py`; no ORM object crosses a port |
| 10 | Transaction boundaries; atomic scan persistence | **PASS** | Rollback verified against a real database |
| 11 | Deterministic identity; re-persisting is idempotent | **PASS** | `test_14_persisting_the_same_scan_twice_is_safe` |
| 12 | Tenant isolation enforced structurally | **PASS** | §3.4 |
| 13 | AWS **and** Azure persist through one schema | **PASS** | `test_10_aws_and_azure_coexist` |
| 14 | Indexes for the real query patterns | **PASS** | 18 named indexes; tenant-leading rule asserted |
| 15 | No credentials or secrets persisted | **PASS** | §3.5 — 46 database-free tests |
| 16 | Database credentials from environment / secret management | **PASS** | §3.5 |
| 17 | Alembic migration, reversible, repeatable | **PASS** | §3.6 — executed |
| 18 | Migration agrees with the ORM models | **PASS** | Schema-parity test: empty diff |
| 19 | Docker compose for local PostgreSQL | **PASS (validated, not launched)** | `docker compose config` validates; no Docker daemon here to start it — §4 |
| 20 | All 17 Part-22 test scenarios | **PASS** | §3.7 — mapped test by test |
| 21 | Phase 3 still green | **PASS** | 898 passed, 0 failed |
| 22 | Quality gates (pytest / ruff / mypy) | **PASS** | §2 |
| 23 | Documentation: design doc, ADR, this report | **PASS** | All three delivered |
| 24 | Nothing from Part 27 implemented early | **PASS** | §3.8 |
| — | `terraform validate` | **NOT VERIFIED** | Sandbox egress policy blocks the Terraform registry — §4 |
| — | Production performance validation | **NOT VERIFIED** | Needs production data volumes — §4 |
| — | Push to remote branch | **BLOCKED** | Credentials are read-only; push authorization was declined — §5 |

**24 PASS · 0 FAIL · 2 NOT VERIFIED (stated, not claimed) · 1 BLOCKED**

---

## 2. Quality gates — executed

```
$ python3 -m pytest -q
898 passed, 60 skipped in 13.79s

$ python3 -m pytest tests/integration/persistence/test_persistence.py -q
36 passed in 5.30s

$ python3 -m pytest tests/integration/persistence/test_migrations.py -q
11 passed in 2.11s

$ python3 -m pytest tests/unit/infrastructure/test_persistence_security.py -q
46 passed in 0.33s

$ ruff check .
All checks passed!

$ mypy domain application infrastructure contracts
Success: no issues found in 132 source files

$ psql -Atc "SHOW server_version"
16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)
```

### About the 60 skips

They are the **Phase 3 AWS and Azure cloud integration tests**, which
require real cloud credentials that do not exist in this environment.
They are reported as skipped. They are not counted as passing anywhere in
this document.

The Phase 4 persistence tests are **not** among them: PostgreSQL is
available here, so all 47 ran for real.

---

## 3. Evidence per requirement

### 3.1 No prohibited persistence technology

The only database driver in use is `psycopg` (PostgreSQL), via
SQLAlchemy. No `pymongo`, no `redis`, no `elasticsearch`, and no
`sqlite3` import anywhere in `domain/`, `application/` or
`infrastructure/`. SQLite is not used as a test substitute either — the
persistence suite skips rather than silently swapping engines, because
JSONB, `ON CONFLICT`, CHECK constraints and transactional rollback are
precisely what is under test.

### 3.2 Domain purity

An AST scan of every file under `domain/` for imports of `sqlalchemy`,
`psycopg`, `alembic`, `infrastructure` or `application`:

```
violations: none
```

The same check over `application/` for `sqlalchemy`, `psycopg`,
`alembic`, `infrastructure`:

```
violations: none
```

Both are also permanently asserted in the suite
(`TestPersistenceDoesNotWeakenDomainPurity`), parsed from the AST rather
than grepped — several domain docstrings legitimately *mention*
SQLAlchemy while explaining why the domain avoids it, and a substring
match would either fail on those or be weakened until it caught nothing.

### 3.3 Additive, not a redesign

Phase 4 added `domain/scans/`, `application/ports/persistence/`,
`application/scanning/persist_scan.py`, and
`infrastructure/persistence/`. It did **not** modify the rule engine, the
DSL, `ResourceGraph`, `Finding`, the conformance framework, the
collectors, or the rule catalogs.

Four pre-existing files were changed, all of them fixes rather than
redesigns:

| File | Change | Why |
|---|---|---|
| `application/scanning/scan_cloud_account.py` | Pass `graph` to `EvaluateRules`; derive a unique `scan_id` | Audit defects 1 and 2 — defect 1 broke Phase 3's own production scan path |
| `application/rules/evaluate_rules.py` | Use the `unknown-account` sentinel instead of rendering `None` | Audit defect 3 |
| `application/scanning/persist_scan.py` | Coverage keyed on full identity | Defect found by the new integration suite — §3.9 |
| `domain/shared/identifiers.py` | Added the shared `UNKNOWN_ACCOUNT` constant | Four call sites must agree on it byte-for-byte |

### 3.4 Tenant isolation

Three independent layers, all tested:

1. Every port method takes `tenant_id` — mandatory, never inferred.
2. Every `SELECT` filters on it, including those that also filter on a
   globally-unique primary key (redundant today, uniform in review).
3. `PersistScanResult` re-verifies every resource and finding against the
   scan's tenant before writing, raising `TenantIsolationViolation`.

```
TestTenantIsolation::test_9_two_tenants_are_fully_isolated               PASSED
TestTenantIsolation::test_tenant_a_cannot_read_tenant_b_scan_by_key      PASSED
TestTenantIsolation::test_tenant_a_cannot_read_tenant_b_findings         PASSED
TestTenantIsolation::test_persisting_a_foreign_tenant_resource_is_refused PASSED
```

### 3.5 Secrets

**Nothing that could authenticate anyone is stored.** Two mechanisms:

- *Structural*: no table declares a credential-shaped column, asserted
  by scanning `Base.metadata` — so persisting a secret would require
  adding a column, visible in a migration review.
- *Defensive*: `attributes` and `evidence` (the two open-ended JSONB
  columns) pass through `redact()` on the way in, matching on key names,
  recursing into nested mappings and lists, with an allowlist for keys
  that name a credential without carrying one.

Database credentials come from `COMPLIANCEIQ_DB_*` environment
variables. `DatabaseConfig.password` is `repr=False` with a custom
`__repr__`; `safe_url` exists for logging. `alembic.ini` contains **no**
`sqlalchemy.url` — the stock Alembic template commits a full connection
string, and a test fails the build if one is ever added back.

All 46 of these tests run **without** a database, deliberately: the
integration suite skips when PostgreSQL is unreachable, which is exactly
the situation where a credential regression would otherwise slip through.

### 3.6 Migration

```
$ alembic upgrade head
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 0001, Initial ComplianceIQ persistence schema (Phase 4).

$ psql -Atc "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1"
alembic_version
finding_snapshots
logical_findings
resource_snapshots
rule_versions
scan_errors
scans
```

Verified by the 11 migration tests: creates every table, stamps the
revision, is safe to run repeatedly, foreign keys cascade to `scans`,
CHECK constraints exist in the real database, the cross-account
uniqueness constraint survives, every query index leads with `tenant_id`,
`downgrade base` removes everything, upgrade→downgrade→upgrade is
replayable, the migration and the ORM models produce an **empty**
autogenerate diff, and a real scan persists end to end against the
migrated schema.

### 3.7 The 17 Part-22 scenarios

| # | Scenario | Test |
|---|---|---|
| 1 | Scan created | `test_1_and_2_scan_created_and_completed` |
| 2 | Scan completed | `test_1_and_2_scan_created_and_completed` |
| 3 | Scan failed | `test_3_failed_scan_is_persisted_as_failed` |
| 4 | Scan partial | `test_4_partial_scan_is_distinguishable_from_completed` |
| 5 | Findings persisted | `test_5_findings_are_persisted_with_full_fidelity` |
| 6 | Finding persists across scans | `test_6_and_12_finding_persists_as_one_logical_row_across_scans` |
| 7 | Finding resolved | `test_7_finding_absent_from_a_covering_scan_is_resolved` |
| 8 | Finding reopened | `test_8_regression_reopens_the_same_logical_finding` |
| 9 | Multi-tenant isolation | `test_9_two_tenants_are_fully_isolated` |
| 10 | AWS + Azure coexist | `test_10_aws_and_azure_coexist` |
| 11 | Same resource id, two accounts | `test_11_same_resource_id_in_two_accounts_does_not_collide` |
| 12 | Logical finding tracked across scans | `test_6_and_12_finding_persists_as_one_logical_row_across_scans` |
| 13 | Rollback on failure | `test_13_rollback_on_persistence_failure_leaves_nothing_behind` |
| 14 | Duplicate persistence is safe | `test_14_persisting_the_same_scan_twice_is_safe` |
| 15 | Empty scan | `test_15_empty_scan_persists_cleanly` |
| 16 | Zero findings | `test_16_scan_with_resources_but_zero_findings` |
| 17 | Large batch | `test_17_large_finding_batch` (2,500 rows) |

All 17 passed against real PostgreSQL.

### 3.8 Nothing from Part 27 built early

No FastAPI, no HTTP layer, no frontend, no React, no mobile, no SIEM
integration, no RAG, no AI, no chatbot, no risk engine, no RBAC, no
authentication, no authorization. Grep confirms no `fastapi`, `flask`,
`django`, or `starlette` import anywhere in the repository.

### 3.9 The defect the integration tests found

Worth recording, because it is the clearest argument for testing against
a real database.

`PersistScanResult` keyed its "was this resource re-examined?" coverage
set on `resource_id` alone. Resource ids are unique only *within an
account*. So scanning account `222…` "covered" `bucket-1` and silently
**resolved** the different `bucket-1` in account `111…` — a live security
issue disappearing from the dashboard without being fixed. The same hole
existed across providers, where an AWS bucket and an Azure storage
account can share a name outright.

The unit tests could not catch it: they persisted both accounts within
one scan, which is the case that works. It took two sequential scans
against a real database.

Fixed by keying coverage on the full `(provider, account, resource)`
identity, matching how logical findings are identified everywhere else.
Two unit regression tests now pin both axes, so the guard cannot be lost
when no database is present.

This is the second time in this project that testing the real thing found
a defect a fake could not; Phase 3's conformance framework found the
first (a Key Vault rule firing against storage accounts).

---

## 4. Not verified — stated plainly

| Item | Why not | What would verify it |
|---|---|---|
| `docker compose up` | The Docker CLI is installed and `docker compose -f docker/postgres/compose.yaml config` **validates the file** (syntax, schema, service definition). But no Docker daemon is running in this sandbox — `/var/run/docker.sock` does not exist — so the container was never **started**, and the init SQL never executed. The same PostgreSQL 16 the compose file describes was exercised directly instead, so the schema, migrations and tests are genuinely verified; only the container packaging is not. | `docker compose -f docker/postgres/compose.yaml up -d` on a machine with a running daemon |
| `terraform validate` | The sandbox's egress policy returns HTTP 403 from `registry.terraform.io`, so providers cannot be initialized. Unchanged from Phase 3; Phase 4 did not touch Terraform. The configuration is `fmt`-clean. | `terraform init && terraform validate` with registry access |
| Production performance | The 2,500-row batching test proves correctness at that size on this machine. No `EXPLAIN` plan was captured under realistic volume, and no index was tuned against production data. | Load testing against representative data volumes |
| Concurrent scan persistence | Two scans of the same account persisting simultaneously should be safe by construction (deterministic keys + `ON CONFLICT`), but this was not measured. | A concurrency test with real parallel writers |

None of these are marked PASS anywhere in this report.

---

## 5. Outstanding: the work is committed but not pushed

All Phase 4 work is committed locally on
`claude/complianceiq-phase-1-domain-hdsj3c`. It has **not** been pushed.

- `git push` returns HTTP 403; the session's credentials are read-only
  (fetch succeeds, push does not).
- A request to attach the repository with push access was **declined**,
  so no further push attempt was made.
- Separately, the remote branch has diverged: it carries one commit the
  local branch does not — `abccba1`, "Implement Phase 2 application
  layer" (32 files, +2,223 lines, authored 11 August).

  Inspecting it shows it is **an earlier, independent implementation of
  the same Phase 2 application layer** this branch already contains: the
  same modules (`evaluate_rules.py`, `scan_cloud_account.py`,
  `build_resource_graph.py`, `dtos.py`, …), which Phases 3 and 4 have
  since extended considerably. It is not new work layered on top; it is a
  parallel take on work already superseded here.

  That makes the resolution a judgment call rather than a mechanical one,
  and it is **left to the repository owner**:

  - *Rebase onto it* — conflicts on essentially every `application/`
    file, each resolved in favour of the local version, since the local
    version is strictly further along. Preserves the commit in history at
    the cost of a large, almost entirely mechanical conflict resolution.
  - *Force-push with lease* — discards `abccba1`. Loses no functionality
    (this branch implements all of it and more) but does discard someone
    else's commit, which should not happen without their agreement.

  Neither was performed. Both are irreversible from the remote's point of
  view, pushing is not currently authorized, and choosing between them
  belongs to whoever owns that commit.

Nothing is lost; the commits exist locally. But this container is
ephemeral, so the work needs pushing before the session ends.

---

## 6. What Phase 5 can build on

The read models are already the API's contract, typed as frozen
dataclasses so the HTTP layer serializes a contract rather than inventing
one:

| Read model | Endpoint it is shaped for |
|---|---|
| `ComplianceSnapshot` | `GET /scans/{key}/compliance` |
| `FindingHistoryEntry` | `GET /findings/{logical_id}/history` |
| `SeverityBreakdown` | Dashboard summary tiles |

`PersistScanResult.execute()` returns a `PersistenceOutcome` — rows
written, newly resolved, newly reopened, duration — returned rather than
logged, so Phase 5 chooses its own logging and metrics stack.

The known gaps Phase 5 or later should address: row-level security
alongside authentication, a retention/partitioning policy for
`finding_snapshots`, and performance validation against real volumes.
