# Multi-tenancy

Tenant isolation is the security property this platform is judged on. A
CSPM product that leaks one customer's findings to another has failed at
the thing it sells.

## The rule

> The tenant comes from the **verified token**. Never from a query
> parameter, a header, a path segment, or a request body.

## Four independent enforcement points

Any one of these alone would be a single point of failure.

### 1. The API surface has no tenant parameter

Not "ignored" — absent. `GET /findings?tenant_id=globex` returns the
caller's own tenant's data, because nothing reads that parameter. A test
asserts no route handler declares a `tenant_id` argument, parsed from the
AST, and another asserts no OpenAPI operation documents one.

`ScanRequest` uses Pydantic `extra="forbid"`, so sending `tenant_id` in a
body is a 422 rather than a silently dropped field. That closes the
mass-assignment variant of the same mistake.

### 2. The type system

`AuthenticatedIdentity` is constructible only by a `TokenVerifier`
implementation. Holding one is proof a signature was verified. A route
handler cannot fabricate an identity without deliberately importing the
class and constructing it by hand — visible in review.

### 3. The ports

Every repository method takes `tenant_id` as a mandatory keyword. Not
optional, not defaulted. A method that cannot be called without naming a
tenant cannot accidentally return another tenant's rows.

### 4. The queries

Every `SELECT` carries `WHERE tenant_id = :tenant_id`, including those
that also filter on a globally-unique primary key. Redundant today; there
so the pattern is uniform and a missing filter is visible in review.

`PersistScanResult` additionally re-verifies every resource and finding
against the scan's tenant before writing, raising
`TenantIsolationViolation`. That is the last point before data becomes
permanent.

## 404, not 403 — and why

A resource belonging to another tenant returns **exactly** what a
non-existent one returns:

```
GET /api/v1/findings/<another-tenant's-real-id>   → 404 not_found
GET /api/v1/findings/definitely-does-not-exist    → 404 not_found
```

Same status, same code, same message. Byte-identical, and there is a test
asserting it.

403 would confirm the id exists. That is an information leak even though
the data is never returned: a caller could enumerate another tenant's
finding ids, learn how many resources they run, and infer their cloud
footprint.

The cost is real — a legitimate caller with a typo cannot distinguish it
from a permissions problem — and it is the right trade for a security
boundary. `tenant_isolation_violation` is logged at ERROR internally so
operators can see what a client cannot.

## Tests

`tests/api/test_security.py::TestTenantIsolation` uses two tenants whose
findings deliberately share resource ids and rule ids. A single-tenant
fixture cannot detect a missing filter — every query would return the
right answer by accident.
