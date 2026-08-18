# Phase 4 — PostgreSQL Persistence & Scan History

> Every claim in this document was verified by running the code. Test
> counts, migration output and schema listings are real output from this
> repository, not illustrations. Where something could **not** be
> verified in this environment, it says so explicitly.

Phase 3 could scan a cloud account and tell you what was wrong with it —
once. The findings lived in memory and vanished. Phase 4 makes that
history durable, and in doing so answers the questions a compliance
platform exists to answer:

- What was our compliance posture on 12 March?
- Is this a new problem, or has it been open for six months?
- We fixed this in April — did it come back?
- What changed between the last two scans?

None of those are storage questions. They are **identity and lifecycle**
questions, and the storage design follows from them.

---

## Contents

1. [What Phase 4 adds](#1-what-phase-4-adds)
2. [Architecture and layering](#2-architecture-and-layering)
3. [The schema](#3-the-schema)
4. [Identity: why there are no UUIDs](#4-identity-why-there-are-no-uuids)
5. [The scan lifecycle](#5-the-scan-lifecycle)
6. [The finding lifecycle](#6-the-finding-lifecycle)
7. [Ports and repositories](#7-ports-and-repositories)
8. [Transaction boundaries and the Unit of Work](#8-transaction-boundaries-and-the-unit-of-work)
9. [Mapping domain objects to rows](#9-mapping-domain-objects-to-rows)
10. [Indexes and query performance](#10-indexes-and-query-performance)
11. [Tenant isolation](#11-tenant-isolation)
12. [Configuration and secrets](#12-configuration-and-secrets)
13. [Migrations](#13-migrations)
14. [Multi-cloud: one schema, two providers](#14-multi-cloud-one-schema-two-providers)
15. [Testing strategy](#15-testing-strategy)
16. [Deliberate deviations, limits, and what Phase 5 needs](#16-deliberate-deviations-limits-and-what-phase-5-needs)

---

## 1. What Phase 4 adds

| Layer | Added | Lines |
|---|---|---|
| Domain | `domain/scans/models.py` — `Scan` aggregate, `ScanTarget`, `ScanCounts`, `ScanError`, `ScanStatus` | 386 |
| Domain | `domain/scans/lifecycle.py` — `LogicalFinding`, `LifecycleState` | 256 |
| Application | `application/ports/persistence/repositories.py` — 5 ports + 3 read models | 285 |
| Application | `application/ports/persistence/unit_of_work.py` — the transaction port | 74 |
| Application | `application/scanning/persist_scan.py` — `PersistScanResult` use case | 247 |
| Infrastructure | ORM models, mappers, redaction, repositories, session, migrations | ~1,580 |

Phases 1–3 were **not modified** beyond fixing the three defects the
[pre-implementation audit](phase-4-persistence-audit.md) found, plus one
cross-account lifecycle defect the new integration suite caught (§15.3).
The rule engine, DSL, resource graph, `Finding`, and conformance
framework are untouched.

### What Phase 4 deliberately does not add

No FastAPI endpoints, no HTTP layer, no frontend, no authentication or
authorization, no SIEM integration, no risk engine, no AI. Those are
later phases. Phase 4 stops at the point where a scan result becomes
durable, queryable history.

---

## 2. Architecture and layering

The dependency rule from Phase 1 is unchanged, and Phase 4's central
constraint is that persistence must not weaken it:

```
        domain/            ← knows nothing about anything
           ▲
           │
      application/         ← use cases; depends on PORTS, not adapters
           ▲
           │  (ports/persistence/*.py — abstract)
           │
    infrastructure/        ← SQLAlchemy, psycopg, Alembic live ONLY here
```

Concretely, the domain imports no `sqlalchemy`, no `psycopg`, no
`alembic`, and no `infrastructure` module. This is not a convention —
it is asserted from the AST of every file under `domain/`:

```
tests/unit/infrastructure/test_persistence_security.py
    ::TestPersistenceDoesNotWeakenDomainPurity
    ::test_domain_modules_import_no_persistence_technology
```

Parsed rather than grepped, deliberately: several domain docstrings
*mention* SQLAlchemy while explaining why the domain avoids it, and a
substring search would either fail on those or be weakened until it
caught nothing. AST parsing also catches an import hidden inside a
function body, which a grep for leading `import` would miss.

The same test asserts the `UnitOfWork` port itself is technology-free —
the port is where an ORM most plausibly leaks upward, because it is
tempting to type it as a `Session`.

### Why the ORM models are not the domain models

`PostgresScanModel` is not `domain.scans.models.Scan`, and no repository
ever returns one. The domain models are frozen, slotted dataclasses with
validating constructors; an ORM instance could not satisfy those
invariants even in principle. Automatic mapping would either bypass the
validators — silently admitting invalid data on read — or fight them.
Two model sets plus explicit mappers (§9) is more code and a better
guarantee.

---

## 3. The schema

Six tables.

```
scans ──┬── scan_errors           (structured partial failures)
        ├── resource_snapshots    (what each resource looked like)
        └── finding_snapshots     (what was wrong, in this scan)

logical_findings                  (the cross-scan life of one issue)
rule_versions                     (rule metadata, once per version)
```

| Table | Grain | Why it exists |
|---|---|---|
| `scans` | one scan execution | The root record, plus denormalized summary counts |
| `scan_errors` | one partial failure | "KMS collection was denied" must be visible, not a log line |
| `resource_snapshots` | one resource per scan | Evidence for a finding, and the input to drift detection |
| `finding_snapshots` | one finding per scan | The immutable observation: what was true at that moment |
| `logical_findings` | one issue, across all scans | The mutable lifecycle: open → resolved → reopened |
| `rule_versions` | one rule version | Rule metadata, stored once instead of per finding |

> **Added after Phase 4.** Migration `0002` adds `compliance_scores` and
> `audit_events` (see [phase-5-core-platform.md](phase-5-core-platform.md));
> `0003` adds graph-context columns to `finding_snapshots`; `0004` adds
> `attack_paths` (see [attack-path-analysis.md](attack-path-analysis.md)
> §16). The six above are Phase 4's scope, not the current table count —
> the psql listing later in this document is a Phase 4 snapshot for the
> same reason.

### The distinction that matters: snapshots vs lifecycle

`finding_snapshots` is **append-only history**. A row says "during scan
X, bucket-1 failed rule s3-bucket-public". That is a historical fact and
is never updated.

`logical_findings` is **current state**. One row says "the s3-bucket-public
problem on bucket-1 in account 111… was first seen on 1 January, last
seen yesterday, has been open for 43 days, and was fixed and regressed
twice". That row is updated by every scan.

Collapsing these into one table is the most common mistake in this
design, and it destroys the product: you either lose history (updating
in place) or lose the notion of a persistent issue (inserting every
time, so a six-month-old problem looks like 180 brand-new ones).

### Structured columns vs JSONB

Everything a query filters, sorts or groups by is a real, typed column.
Everything provider-specific and unenumerable is `JSONB`:

```python
resource_type: Mapped[str]  = mapped_column(String(128), nullable=False)   # queried
attributes:   Mapped[dict]  = mapped_column(JSONB,       nullable=False)   # open-ended
```

`JSONB` rather than `JSON`: binary storage, GIN-indexable, key
deduplication. `JSON`'s only advantage is preserving key order and
whitespace, which is irrelevant here.

Putting everything in JSONB would be faster to write and permanently
slower to use — you cannot efficiently index or constrain what the
database cannot see.

### Enums as TEXT + CHECK, not native ENUM

```python
CheckConstraint("status IN ('queued','running','completed','partial','failed','cancelled')",
                name="ck_scans_status")
```

`CloudProvider` is explicitly expected to grow (GCP is next). Extending
a native PostgreSQL enum requires `ALTER TYPE`, which takes a lock;
changing a CHECK constraint is an ordinary `ALTER TABLE` in a migration.
The constraint still gives the real benefit — the database rejects a
value the application considers impossible, so a bug or a manual
`UPDATE` cannot corrupt the vocabulary.

Seventeen CHECK constraints encode domain invariants at rest, including:

| Constraint | Invariant |
|---|---|
| `ck_scans_terminal_has_completed_at` | A terminal scan has a completion time; a running one does not |
| `ck_scans_completed_after_started` | Time moves forwards |
| `ck_logical_findings_seen_order` | `last_seen_at >= first_seen_at` |
| `ck_logical_findings_resolved_has_time` | A RESOLVED finding carries `resolved_at` |
| `ck_findings_no_self_supersede` | A finding cannot supersede itself |
| `ck_findings_risk_bounded` | Risk is 0–100 or absent |

These duplicate checks the domain aggregates already perform. That is
the point: the domain protects the write path this codebase controls,
and the constraint protects the database from every other write path
that will ever exist.

---

## 4. Identity: why there are no UUIDs

Every primary key in this schema is **deterministic and derived from
meaning**. There is no `id UUID DEFAULT gen_random_uuid()` anywhere.

```
scan_key            = tenant | provider|account|directory | started_at
logical_finding_id  = tenant : account : resource : rule
finding_id          = logical_finding_id : scan_key
```

The reason is idempotency. A scan pipeline retries — the network drops,
the process is killed mid-persist, a queue redelivers a message. With a
random key, persisting the same scan twice produces two scans, double
the findings, and a compliance score computed from duplicated data. With
a derived key, the second attempt collides with the first and
`ON CONFLICT DO UPDATE` makes it a no-op:

```
tests/integration/persistence/test_persistence.py
    ::TestTransactionsAndIdempotency::test_14_persisting_the_same_scan_twice_is_safe
```

It also means a finding's identity is reproducible from the finding
itself. Two independent scanners observing the same misconfiguration
derive the same `logical_finding_id` without coordinating.

### The separator, and a Phase 3 defect

`ScanTarget.scope_key` uses `|`, not `:`. The audit found that
`logical_finding_id`'s `:` separator collides with the `:` inside every
ARN and Azure resource id, making the string unparseable. Rather than
re-encode it, Phase 4 treats it as **opaque** and stores the identity
*components* as separate columns:

```python
UniqueConstraint("tenant_id", "provider", "account_id", "resource_id", "rule_id",
                 name="uq_logical_finding_identity")
```

Identity is therefore meaningful and enforced even though the string is
not parseable. Nothing in Phase 4 ever splits that string.

### `unknown-account`

When a credential lacks `sts:GetCallerIdentity` (a documented non-fatal
case), the account component becomes the literal `unknown-account`. It
does not make two such accounts distinguishable — nothing could — but it
is honest about being unknown rather than rendering `None`, which Phase 3
did and which produced the string `"None"` inside identity keys.

It is a single shared constant (`domain/shared/identifiers.py`) rather
than a repeated literal, because four call sites must agree on it
byte-for-byte; a divergence between any two would surface as findings
that never resolve.

---

## 5. The scan lifecycle

```
                 ┌──────────┐
                 │  QUEUED  │
                 └────┬─────┘
                      │ start()
                 ┌────▼─────┐
                 │ RUNNING  │
                 └────┬─────┘
      ┌───────────────┼───────────────┬──────────────┐
      │ complete()    │ complete_     │ fail()       │ cancel()
      │               │ partially()   │              │
┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐  ┌─────▼─────┐
│ COMPLETED │   │  PARTIAL  │   │  FAILED   │  │ CANCELLED │
└───────────┘   └───────────┘   └───────────┘  └───────────┘
                        all terminal
```

The transition table lives in the domain (`_ALLOWED_TRANSITIONS`) and
illegal transitions raise `InvalidScan`. Terminal states are terminal:
a COMPLETED scan cannot be re-completed or failed.

**PARTIAL is not a nicety.** A scan that could enumerate S3 but was
denied KMS has not "completed" — reporting it as COMPLETED tells an
auditor that KMS was checked and found compliant, which is false. The
aggregate refuses:

```python
if errors:
    final = scan.complete_partially(completed_at=..., counts=..., errors=errors)
else:
    final = scan.complete(completed_at=..., counts=...)
```

and `Scan.complete()` raises if errors are present at all. The database
mirrors it (`ck_scans_terminal_has_completed_at`).

### Why counts are stored, not computed

`scans` carries `resource_count`, `finding_count`, per-severity counts,
`pass`/`fail`/`indeterminate`, and `error_count`. These are derivable by
aggregating `finding_snapshots` — and they are stored anyway, because
the dashboard's landing page shows the last 50 scans and would otherwise
run 50 aggregations over the largest table in the database to render one
screen. They are written inside the same transaction as the rows they
summarize (§8), so they cannot describe data that failed to land.

Severity counts count **failing findings only**. A passing check is not
a "low-severity finding"; counting it as one would make the severity
breakdown meaningless.

---

## 6. The finding lifecycle

This is the heart of Phase 4.

```
   first observed
         │
    ┌────▼────┐  seen again    ┌──────────┐
    │  OPEN   │───────────────▶│ REOPENED │
    └────┬────┘                └────┬─────┘
         │ absent, resource covered │ absent, resource covered
    ┌────▼─────┐                    │
    │ RESOLVED │◀───────────────────┘
    └────┬─────┘
         │ seen again  →  REOPENED (reopen_count += 1)
         └──────────────────────────┘

   OPEN / REOPENED ──suppress(reason)──▶ SUPPRESSED ──unsuppress──▶ (prior state)
```

Four behaviours are worth calling out, each because the obvious
implementation is wrong.

**Nothing is ever deleted.** A fixed finding becomes RESOLVED and keeps
its `first_seen_at`. Deleting it would erase the fact that the
organization was exposed for six weeks, which is exactly what an audit
asks about.

**REOPENED is distinct from OPEN.** A control that was fixed and broke
again is a different signal from one that was never fixed — it usually
means a process failure rather than an oversight, and `reopen_count`
makes "which rules keep regressing?" a query rather than an
investigation.

**`first_seen_at` never moves.** Not through resolution, not through
regression. The original discovery date is the number an auditor asks
for.

**A finding is only resolved if its resource was actually re-examined.**
This is the precondition that matters most:

```python
covered_resources = {
    (r.cloud_provider, account_key(r.account_id), r.resource_id)
    for r in scan_result.resources
}
...
if (tracked.provider, account_key(tracked.account_id), tracked.resource_id) not in covered_resources:
    continue   # not re-examined this scan — leave it alone
```

A resource missing from a scan because collection *failed* has not been
fixed. Treating absence as proof of remediation would silently close
live security issues, which is the worst failure mode this system has:
the problem disappears from the dashboard while still being exploitable.

The coverage key is the full `(provider, account, resource)` identity for
the same reason the uniqueness constraint is. Keying it on `resource_id`
alone was a real defect in the first implementation — see §15.3.

Lifecycle timestamps use the **scan's** time, not the persistence time,
so `first_seen_at` agrees with the finding's `detected_at`. Both mean
"when the cloud was in this state". If persistence used its own clock,
an audit comparing a finding to its lifecycle row would see two
different discovery dates, and the gap would grow with however long
persistence took.

---

## 7. Ports and repositories

Five ports in `application/ports/persistence/repositories.py`:

| Port | Responsibility |
|---|---|
| `ScanRepository` | Create, update status, save, get, list recent, record errors |
| `ResourceSnapshotRepository` | Bulk save; fetch for a scan; resource history |
| `FindingSnapshotRepository` | Bulk save; fetch for a scan (status/severity filtered); history by logical id |
| `LogicalFindingRepository` | Active findings; lookup by logical ids; bulk upsert; by state |
| `ScanHistoryQueryRepository` | Compliance snapshot, compliance history, counts by dimension, rule regressions |

Three design rules, all visible in the file:

**Ports are shaped by use cases, not by tables.** There is no
`ScanTargetRepository` even though the target is persisted, because
nothing needs one independently of its scan. `ScanHistoryQueryRepository`
spans several tables because that is what a dashboard actually asks for.
A repository per table is a schema browser, not a domain interface.

**Every method takes `tenant_id` explicitly**, never optionally, never
from ambient state (§11).

**Domain objects in, domain objects out.** No ORM instance, `Session`,
`Row`, or SQL string crosses the boundary in either direction. Read
models (`ComplianceSnapshot`, `FindingHistoryEntry`, `SeverityBreakdown`)
are frozen dataclasses, so Phase 5's API gets a typed contract rather
than a bag of dict keys.

### `ComplianceSnapshot.score` and hidden compliance

```python
determinate = self.pass_count + self.fail_count
if determinate == 0:
    return None
return round(100.0 * self.pass_count / determinate, 2)
```

INDETERMINATE findings are excluded from the denominator, not counted as
passes, and a scan with nothing determinate scores `None` rather than
100%. Phase 3 built three-valued logic specifically so that "we could not
check this" never masquerades as "this is fine"; an averaging formula
that quietly rounded unknowns up to compliant would reintroduce exactly
that, one layer lower.

### Bulk writes

A scan of a large account produces tens of thousands of rows.
Row-by-row `INSERT` is one round trip each; the repositories batch:

```python
BATCH_SIZE = 1000   # PostgreSQL's hard limit is 65535 bind parameters per
                    # statement; at ~20 columns a 1000-row batch is ~20000.
```

Verified with a 2,500-resource scan:

```
tests/integration/persistence/test_persistence.py
    ::TestTransactionsAndIdempotency::test_17_large_finding_batch
```

---

## 8. Transaction boundaries and the Unit of Work

**One scan is one transaction.** Resources, findings, lifecycle rows,
scan errors and the summary counts either all land or none do.

Half a scan is worse than no scan: a findings table without its summary,
or findings without the resource snapshots that explain them, is a
security record nobody can trust — and, unlike a missing scan, it looks
complete.

```python
with self._uow as uow:
    uow.scans.create(scan)
    uow.resource_snapshots.save_all(...)
    uow.finding_snapshots.save_all(...)
    ...reconcile lifecycle...
    uow.logical_findings.upsert_all(...)
    uow.scans.save(final)      # summary LAST
    uow.commit()
```

Two properties make this structural rather than remembered:

**All five repositories are built from the same `Session`.** They
provably participate in one transaction; the alternative — each
repository opening its own connection — is how "atomic" persistence
quietly stops being atomic.

**Rollback is the default, not the exception path.** `__exit__` rolls
back unless `commit()` was called:

```python
def __exit__(self, exc_type, exc, traceback):
    try:
        if not self._committed:
            self.rollback()
    finally:
        ...
```

That covers both the exception path and the forgot-to-commit path,
including an early `return` added by a future refactor. Verified against
a real database by injecting a mid-write failure and asserting the scan
row is absent afterwards:

```
::TestTransactionsAndIdempotency::test_13_rollback_on_persistence_failure_leaves_nothing_behind
```

Migrations get the same treatment: PostgreSQL supports transactional
DDL, and `env.py` wraps the whole run in one transaction, so a migration
that fails halfway leaves the old schema rather than a hybrid.

---

## 9. Mapping domain objects to rows

Every translation is hand-written, one direction at a time, in
`infrastructure/persistence/postgres/mappers/mappers.py`. No
`registry.map_imperatively`, no dataclass-to-ORM magic.

- `*_to_row` returns a **plain dict** for bulk insert — the repositories
  use Core bulk operations, where ORM instances would be pure overhead.
- `*_to_domain` passes through the real domain constructor, so every
  invariant is re-checked on the way out. A corrupted row fails loudly
  instead of propagating into the rule engine.

The cost is real (~350 lines) and buys three things: every field's round
trip is reviewable, a schema change that drops a field breaks a test
rather than losing data quietly, and the domain constructors keep their
validators.

One clock is read in this layer, in one function, for `created_at` /
`updated_at` — columns that record when a *row* was written. No
domain-meaningful timestamp is ever generated here; they are all passed
in. Domain determinism is unaffected.

---

## 10. Indexes and query performance

Eighteen named query indexes, each traceable to a query the product needs. Every one
leads with `tenant_id`, because every query is tenant-scoped and a
composite index cannot serve a query that does not use its leading
column.

| Index | Query it serves |
|---|---|
| `ix_scans_tenant_started` | The dashboard landing page: recent scans |
| `ix_scans_tenant_provider_account_started` | Compliance history for one account over time |
| `ix_findings_tenant_scan_status` | `GET /scans/{id}/findings?status=fail` |
| `ix_findings_tenant_scan_severity` | The same, filtered by severity |
| `ix_findings_tenant_logical` | `GET /findings/{logical_id}/history` |
| `ix_findings_tenant_resource` | "Everything wrong with this resource" |
| `ix_findings_tenant_rule` | "Everywhere this rule fires" |
| `ix_logical_findings_tenant_state` | "What is wrong right now?" |
| `ix_logical_findings_tenant_reopened` | "Which controls keep regressing?" |
| `ix_resource_snapshots_tenant_resource` | Resource history, and drift input |

The tenant-leading rule is asserted, not just documented:

```
tests/integration/persistence/test_migrations.py
    ::TestUpgrade::test_every_query_index_leads_with_tenant_id
```

It exempts indexes that merely *back* a uniqueness constraint —
`uq_resource_snapshot_scan_resource` leads with `scan_key`, which already
belongs to exactly one tenant, so prefixing it would widen the key for
no benefit. That exemption was added after the test fired on correct
code; the alternative (deleting the test) would have been worse.

### What is not here

No partitioning, no materialized views, no read replicas, no
`pg_stat_statements` analysis, no `EXPLAIN` plans captured under load.
Those are real production concerns and they need production data volumes
to decide. Adding them now would be guessing with extra steps. §16 lists
them as Phase 5+ work.

---

## 11. Tenant isolation

Isolation is structural, enforced in three independent places.

**1. Every port method requires `tenant_id`.** Not optional, not
defaulted, not inferred from ambient state. A method that cannot be
called without naming a tenant cannot accidentally return another
tenant's rows.

**2. Every query filters on it.** Every `SELECT` in
`scan_repository.py` carries `WHERE tenant_id = :tenant_id`, including
those that also filter on a globally-unique primary key — a `scan_key`
is unique, so the filter is redundant *today*, and it is there so that
the pattern is uniform and a missing filter is visible in review.

**3. The use case re-verifies before writing.** `PersistScanResult`
checks every resource and finding against the scan's tenant and raises
`TenantIsolationViolation` on a mismatch, even though upstream already
checked. Defense in depth: this is the last point before data becomes
permanent.

Verified with two tenants writing overlapping resource ids:

```
::TestTenantIsolation::test_9_two_tenants_are_fully_isolated
```

Not implemented: PostgreSQL row-level security. It is the right eventual
answer for a system with multiple database roles, and it is meaningless
while the application connects as a single owner role that bypasses RLS
policies anyway. It belongs with Phase 5's authentication work, listed
in §16 rather than half-built here.

---

## 12. Configuration and secrets

**Nothing that could authenticate anyone is ever stored.** Not cloud
credentials, access keys, secret keys, tokens, passwords, or private
keys. Two independent mechanisms:

### Structural: no column to put one in

No table declares a credential-shaped column. A future change that tries
to persist a secret has to *add* a column, which appears in a migration
review rather than being buried in a collector. Asserted:

```
::TestSchemaHasNoPlaceToStoreASecret::test_no_table_declares_a_credential_shaped_column
```

### Defensive: redaction on the way in

`attributes` and `evidence` are JSONB and open-ended — the two places a
future collector could most plausibly leak something. Both are passed
through `redaction.redact()` before insert. It matches on **key names**,
recurses into nested mappings and lists, and has an allowlist for keys
that *name* a credential without carrying one (`access_key_count` is a
number; `kms_key_id` is an ARN; `key_manager` is `"AWS"` or
`"CUSTOMER"`).

Two deliberate choices: it matches key names rather than value
heuristics (scanning values for "things that look like a secret" produces
false positives on ordinary ARNs and false negatives on anything
unusual), and it redacts rather than raising (a scan that finds one
suspicious key should still persist its other 10,000 findings — dropping
the scan turns a hygiene issue into an outage). The redaction is visible
in the stored data, so it is auditable.

Phase 3's collectors are not known to leak anything; this is a backstop
for the collector nobody has written yet.

### The database's own credentials

Read from the environment (`COMPLIANCEIQ_DB_*`), never from a file in
this repository. `DatabaseConfig.password` is `repr=False` with a custom
`__repr__`, and `safe_url` exists for logging, because a config object
that leaks its own password into a traceback is a real and common way
credentials escape.

`alembic.ini` has **no** `sqlalchemy.url`. The stock Alembic template
commits a full connection string, password included; `env.py` builds the
URL from `DatabaseConfig.from_env()` instead — which also guarantees that
`alembic upgrade head` and the running service cannot disagree about
which database they mean.

All of the above is tested **without** a database, because the
integration suite skips when PostgreSQL is unreachable — precisely the
situation where a credential regression would otherwise go unnoticed:

```
tests/unit/infrastructure/test_persistence_security.py — 46 tests
```

---

## 13. Migrations

One revision so far: `0001_initial_schema`, creating all six tables, 18
named indexes, 17 CHECK constraints and 2 unique constraints.

```bash
export COMPLIANCEIQ_DB_HOST=localhost COMPLIANCEIQ_DB_PASSWORD=...
alembic upgrade head
```

Real output from this repository:

```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 0001, Initial ComplianceIQ persistence schema (Phase 4).
```

```
$ psql -Atc "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY 1"
alembic_version
finding_snapshots
logical_findings
resource_snapshots
rule_versions
scan_errors
scans
```

The migration is **reversible** (`alembic downgrade base` drops
everything, children before parents) and **safe to run repeatedly**,
which matters because deployment pipelines run `upgrade head` on every
boot, including the boots where nothing changed.

### The parity test

Two descriptions of the schema exist — the ORM models the repositories
compile queries against, and the migration that builds the actual
database — and nothing but a test keeps them in step:

```python
context = MigrationContext.configure(conn, opts={"compare_type": True, ...})
diff = compare_metadata(context, Base.metadata)
assert diff == []
```

It builds the database from the **migration**, then asks Alembic what it
would autogenerate to reach the models, and requires an empty diff. When
these drift the symptom is not a clear error at deploy time; it is a
query that passes in the test suite (schema from `create_all`) and fails
in production (schema from the migration). A companion test persists a
real scan end to end against the migrated schema for the same reason.

---

## 14. Multi-cloud: one schema, two providers

Phase 3 ended as a single AWS + Azure engine. Phase 4 persists both
through one schema, with **no provider-specific tables and no
provider-specific columns**.

The mechanism is that `account_id` is provider-agnostic: it holds an AWS
account id, an Azure subscription id, or a future GCP project id, with
`provider` alongside it. `directory_id` carries the Azure tenant
(directory) id where relevant. Adding GCP needs a new value in one CHECK
constraint, not a new table.

Provider is part of lifecycle identity, because an AWS bucket and an
Azure storage account can share a name outright and are obviously
different issues. It appears in `uq_logical_finding_identity` and in the
resolution coverage key (§6).

```
::TestMultiCloudAndMultiAccount::test_10_aws_and_azure_coexist
::TestMultiCloudAndMultiAccount::test_11_same_resource_id_in_two_accounts_does_not_collide
```

---

## 15. Testing strategy

### 15.1 What runs

| Suite | Count | Needs |
|---|---|---|
| Full suite | **898 passed**, 60 skipped | — |
| PostgreSQL persistence | 36 | A real database |
| PostgreSQL migrations | 11 | A real database |
| Part 20 security | 46 | Nothing |
| Skipped | 60 | Real AWS/Azure credentials |

The 60 skips are the Phase 3 cloud integration tests, which need real
cloud accounts. They are honestly reported as skipped, never as passed.

### 15.2 Why the database is real

The persistence suite auto-detects PostgreSQL: reachable means it runs,
unreachable means it **skips with an actionable message**. It never
substitutes SQLite or an in-memory fake, because JSONB, `ON CONFLICT`,
CHECK constraints and transactional rollback are exactly what is under
test and no other engine reproduces them faithfully. A green suite
against a fake would be worse than no suite — it would be a false
assurance about the one component whose whole job is durability.

All 47 database tests in this document were executed against
**PostgreSQL 16.13** in this environment.

### 15.3 The defect the integration suite caught

`PersistScanResult` originally keyed its "was this resource re-examined?"
coverage set on `resource_id` alone. Resource ids are unique only within
an account. So scanning account `222…` "covered" `bucket-1` and silently
**resolved** the different `bucket-1` in account `111…` — a live security
issue vanishing from the dashboard without being fixed. The same hole
existed across providers.

The unit tests could not catch it: they persisted both accounts in one
scan, which is the case that works. It took two scans against a real
database. The fix keys coverage on the full `(provider, account,
resource)` identity, and two unit regression tests now pin both axes so
the guard cannot be lost when no database is present.

This is the second time in this project that a test which exercises the
real thing found a defect that a fake could not; Phase 3's conformance
framework found the first.

### 15.4 Verified gates

```
$ python3 -m pytest -q
898 passed, 60 skipped in 14.06s

$ ruff check .
All checks passed!

$ mypy domain application infrastructure contracts
Success: no issues found in 132 source files
```

---

## 16. Deliberate deviations, limits, and what Phase 5 needs

### Deviations from a literal reading of the brief

**Rule metadata lives in `rule_versions`, not on every finding row.**
The brief asks that title, description, rationale, remediation and
framework mappings be preserved. They are — stored once per
`(rule_id, rule_version)` and joined. Denormalizing a ~2 KB remediation
block onto every finding would multiply it by resources × scans for data
identical across all of them: gigabytes, and a rule-text correction
would require rewriting history. No information is lost; it is stored
once.

### Honest limits

- **No production performance validation.** The 2,500-row batching test
  proves correctness at that size on this machine. It says nothing about
  millions of findings on production hardware. No `EXPLAIN` plan was
  captured under realistic volume.
- **No row-level security** (§11).
- **No retention or archival policy.** `finding_snapshots` grows without
  bound. A real deployment needs partitioning by time and an archival
  rule; both need real volume data to size.
- **No concurrency testing.** Two scans of the same account persisting
  simultaneously should be safe by construction — deterministic keys plus
  `ON CONFLICT` — but "should be" is not "was measured".
- **`terraform validate` still cannot run in this environment.** The
  sandbox's egress policy returns 403 from `registry.terraform.io`. The
  Terraform configuration is `fmt`-clean and unchanged by Phase 4; it is
  not claimed to be validated.

### What Phase 5 can now build on

The read models are the API's contract: `ComplianceSnapshot` is
`GET /scans/{key}/compliance`, `FindingHistoryEntry` is
`GET /findings/{logical_id}/history`, `SeverityBreakdown` is the
dashboard summary. They are typed frozen dataclasses precisely so the
API layer serializes a contract rather than inventing one.

`PersistScanResult.execute()` returns a `PersistenceOutcome` carrying
what actually happened — rows written, newly resolved, newly reopened,
duration — for logging and observability, returned rather than logged so
the caller chooses its own logging stack.

---

## Related documents

- [Phase 4 pre-implementation audit](phase-4-persistence-audit.md) — what
  was found in Phases 1–3 before any code was written
- [ADR-0001: PostgreSQL for scan history](../adr/ADR-0001-phase-4-postgresql-persistence.md)
- [Phase 4 implementation report](phase-4-implementation-report.md) —
  PASS/FAIL against every requirement
- [Phase 1 — Domain](phase-1-domain.md) ·
  [Phase 2 — Application](phase-2-application.md) ·
  [Phase 3 — Infrastructure](phase-3-infrastructure.md)
