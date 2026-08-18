# ADR-0001 — PostgreSQL for scan history and finding lifecycle

- **Status:** Accepted
- **Date:** 2026-08-13
- **Phase:** 4 (Persistence & Scan History)
- **Supersedes:** nothing
- **Related:** [Phase 4 audit](../architecture/phase-4-persistence-audit.md),
  [Phase 4 persistence design](../architecture/phase-4-persistence.md)

---

## Context

At the end of Phase 3, ComplianceIQ could scan AWS and Azure accounts,
evaluate a 68-rule catalog with three-valued logic, and produce findings.
All of it lived in memory and was discarded when the process exited.

That makes the product a linter, not a compliance platform. The questions
customers actually ask are historical:

- What was our compliance posture on a given date?
- Is this finding new, or has it been open for six months?
- We fixed this in April — has it regressed?
- Which controls keep breaking?

None can be answered without durable, queryable history. Phase 4's job is
to provide it without compromising the architecture Phases 1–3 built:
a domain layer that depends on nothing, and an application layer that
depends on ports rather than technology.

The forces in tension:

1. **History must be immutable, but state must be current.** An auditor
   needs to know what was true during scan #47; an operator needs to know
   what is broken *now*.
2. **Writes are bursty and large** (tens of thousands of rows per scan);
   reads are analytical (aggregations over time, filtered by tenant).
3. **Persistence must not leak into the domain**, which is a hard
   constraint from the phase brief and from Phase 1's design.
4. **Multi-tenancy is a security boundary**, not a convenience.
5. **Retries are normal.** Scan pipelines are killed, redelivered and
   re-run; persisting the same scan twice must not corrupt the data.

---

## Decision

**Use PostgreSQL 16 as the single primary persistence technology**,
accessed through SQLAlchemy 2.x Core/ORM behind abstract repository ports,
with Alembic for schema migrations.

The significant sub-decisions:

### 1. Two tables for findings, not one

`finding_snapshots` is append-only history (one row per finding per
scan). `logical_findings` is mutable current state (one row per issue,
across all scans). This is the structural answer to force #1.

### 2. Deterministic, meaning-derived primary keys — no UUIDs

```
scan_key           = tenant | provider|account|directory | started_at
logical_finding_id = tenant : account : resource : rule
finding_id         = logical_finding_id : scan_key
```

Re-persisting a scan collides with itself and `ON CONFLICT DO UPDATE`
makes it a no-op. This is the answer to force #5; a random key would
turn every retry into duplicated history and a wrong compliance score.

Because the `logical_finding_id` string embeds `:` — which also appears
inside every ARN and Azure resource id — it is treated as **opaque** and
never parsed. The identity *components* are separate columns with a
uniqueness constraint over them.

### 3. Ports in the application layer, adapters in infrastructure

Five repository ports plus a `UnitOfWork` port, all abstract, all taking
domain objects and returning domain objects. The concrete PostgreSQL
implementations are injected. The domain imports no SQLAlchemy, no
psycopg, no Alembic, and no infrastructure module — asserted from the AST
of every domain file, not by convention.

### 4. One scan is one transaction

All five repositories share a single `Session`, so they provably
participate in one transaction. `UnitOfWork.__exit__` rolls back unless
`commit()` was called, making rollback the default rather than an
exception path.

### 5. Structured columns for anything queried; JSONB for cloud state

Provider-specific resource attributes and finding evidence are JSONB.
Everything a dashboard filters, sorts or groups by is a typed column with
an index.

### 6. Enums as TEXT + CHECK constraints, not native PostgreSQL ENUMs

`CloudProvider` is expected to grow. Extending a native enum requires
`ALTER TYPE` and a lock; changing a CHECK constraint is an ordinary
migration.

### 7. `tenant_id` mandatory on every repository method, leading every index

Tenant isolation becomes structural: a method that cannot be called
without naming a tenant cannot accidentally return another tenant's rows.

---

## Alternatives considered

### MongoDB (or another document store)

**Rejected.** Superficially attractive: findings and resource attributes
are semi-structured, and schema-per-provider is awkward in SQL.

But the workload is analytical and relational. "Compliance score per
account per month", "findings joined to rule metadata", "resources whose
snapshot changed between two scans" are joins and aggregations. More
decisively, this is a compliance product: the correctness of the history
is the product. Multi-document transactions, CHECK-style constraints and
foreign keys are load-bearing here, and they are exactly what a document
store makes optional. PostgreSQL's JSONB already covers the
semi-structured half without giving up any of it.

### SQLite

**Rejected as the primary store**, and rejected even as a test substitute.
Single-writer, no JSONB, no real concurrency. Using it in tests while
running PostgreSQL in production would be worse than no tests: the suite
would be green about the one component whose entire job is durability,
while never exercising the semantics actually in use.

### Elasticsearch / OpenSearch

**Rejected as primary.** Excellent at full-text search over findings and
plausible as a *secondary* index later. Not a system of record: no
transactions, eventually-consistent reads, and no constraint enforcement.
A compliance record that might not reflect the last write is not a
compliance record.

### Redis

**Rejected, and explicitly out of scope for Phase 4.** In-memory,
non-durable by default. It is a reasonable future cache in front of the
compliance-history queries, and nothing here forecloses that — but it is
not a store of record, and adding a cache before there is a measured
latency problem is speculative.

### Event sourcing (append-only event log, projected state)

**Rejected as over-engineering for this phase.** It is a genuinely good
fit conceptually — finding lifecycle *is* a sequence of events — and the
current design keeps most of the benefit: `finding_snapshots` is already
an append-only log of observations, and `logical_findings` is effectively
a projection of it.

What was rejected is the full apparatus: an event store, replay,
projection rebuilds, eventual consistency between write and read models.
That is a large amount of machinery to operate, and the one thing it buys
over the current design — reconstructing lifecycle state at an arbitrary
past instant — is not a requirement anyone has stated. It remains
available: the snapshot table holds the information needed to rebuild
lifecycle state if it is ever wanted.

### ORM-mapped domain models (SQLAlchemy `map_imperatively`)

**Rejected.** Would have eliminated ~350 lines of explicit mappers. But
the domain models are frozen, slotted dataclasses with validating
constructors, and automatic mapping would either bypass those validators
(admitting invalid data on read) or fight them. Hand-written mappers make
every field's round trip reviewable and force a schema change that drops
a field to break a test rather than lose data quietly.

### A repository per table

**Rejected.** `scan_targets` needs no repository — nothing wants one
independently of its scan — and the dashboard's real question spans
several tables at once. Ports are shaped by use cases; a repository per
table is a schema browser wearing an interface.

---

## Consequences

### Positive

- History is durable, queryable, and transactionally consistent.
- Re-running a scan is safe by construction, not by convention.
- The domain and application layers are unchanged in character: still
  technology-free, still deterministic, still unit-testable with no
  database.
- Finding lifecycle (open → resolved → reopened, with `first_seen_at`
  preserved) is a first-class domain concept with an enforced state
  machine, mirrored by CHECK constraints at rest.
- One schema serves AWS and Azure with no provider-specific tables;
  adding GCP is a CHECK-constraint change.
- Swapping PostgreSQL for something else later means writing new
  adapters, not touching the domain or the use cases.

### Negative / accepted costs

- **Two model sets and hand-written mappers.** More code, deliberately.
- **PostgreSQL is now an operational dependency** — it must be run,
  backed up, migrated and monitored. `docker/postgres/` covers
  development; production operations are not in this phase.
- **The persistence integration tests need a real database.** They skip
  when none is reachable, which means a CI job without a service
  container gets weaker coverage. Mitigated by keeping every
  security-critical assertion (redaction, credential handling, domain
  purity) in database-free unit tests that always run.
- **`finding_snapshots` grows without bound.** No retention or
  partitioning policy yet; both need real volume data to size sensibly.
- **No row-level security.** It is the right eventual answer but is
  meaningless while the application connects as a single owner role. It
  belongs with Phase 5's authentication work.

### Neutral

- Alembic is now the only sanctioned way to change the schema. A parity
  test fails the build if the migration and the ORM models disagree.

---

## Validation

Every claim below was executed in this repository against a real
PostgreSQL 16.13 server:

| Check | Result |
|---|---|
| Full test suite | 898 passed, 60 skipped |
| PostgreSQL persistence integration tests | 36 passed |
| Migration tests (incl. schema parity) | 11 passed |
| `alembic upgrade head` | Applied; 6 tables created |
| `alembic downgrade base` then `upgrade head` | Reversible and replayable |
| `ruff check .` | All checks passed |
| `mypy` | No issues in 132 source files |

The 60 skips are the Phase 3 cloud integration tests, which require real
AWS/Azure credentials unavailable in this environment. They are reported
as skipped, never as passed.
