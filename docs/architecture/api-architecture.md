# API architecture

## Request path

```
HTTP request
   │
   ▼ CorrelationIdMiddleware      establish/preserve X-Correlation-ID
   │
   ▼ SecurityHeadersMiddleware    nosniff, DENY, no-store
   │
   ▼ dependencies.current_identity
   │      Authorization: Bearer → TokenVerifier → AuthenticatedIdentity
   │
   ▼ dependencies.page_request / finding_filters
   │      bounded paging, closed enum vocabularies
   │
   ▼ router                       calls a use case, maps to a schema
   │
   ▼ use case                     enforces role + tenant, calls PORTS
   │
   ▼ repository adapter           SQL, tenant-scoped, DB-side paging
```

Errors leave through one handler set, producing one envelope regardless
of where they were raised.

## Why routers are thin

A router does three things: pull the use case off `app.state`, call it,
map the result to a schema. It contains no business logic, no tenant
filtering, and no persistence.

That is what makes the layering testable rather than aspirational: the
same `create_app` builds the production app and the test app, so the 99
API tests exercise the real routing, real authentication and real error
handling over in-memory adapters.

## Dependency injection via `ApiServices`

`create_app(services)` constructs nothing — no engine, no key pair, no
repository. Everything arrives already built.

A single explicit bundle rather than module-level globals or a service
locator: what the API depends on is enumerable by reading one dataclass,
and a test supplies fakes by filling it in.

`composition.py` is the only module that chooses concrete adapters.

## Versioning

All data endpoints live under `/api/v1`. Operational endpoints
(`/health`, `/version`, `/.well-known/jwks.json`) sit outside it — they
are not part of the versioned data contract and should not move when the
API version does.

**Additive changes ship in v1**: new optional response fields, new error
codes, new endpoints. Clients must ignore unknown fields, or an additive
change becomes an outage.

**Breaking changes require `/api/v2`**: removing or renaming a field,
narrowing an enum, changing a status code, changing an error `code`.

## OpenAPI as a contract artifact

`GET /openapi.json` is the machine-readable contract the AI engineer
generates a client from — not incidental FastAPI output. Tests assert it
declares a bearer security scheme, that every `/api/v1` operation
requires it, that operational endpoints do not, that documented error
responses exist, that enums are published, that paging bounds appear, and
that the AI contract schema has exactly 11 properties.

A checked-in copy lives at `tests/contracts/fixtures/openapi.json`.

## Performance posture

- Filtering, counting and paging happen **in the database**. Loading
  matches into Python and slicing satisfies the port signature and
  defeats its purpose.
- `limit` is bounded at 100 and re-validated in the application layer, so
  there is no code path producing an unbounded query.
- Every query index leads with `tenant_id`, matching how every query
  filters.
- The provider/lifecycle join is added only when those filters are
  actually used, so the common query stays a single-table index scan.

Not done: load testing, `EXPLAIN` analysis under volume, caching.
