# Error contract

Every error response — validation, auth, not-found, unexpected — has one
shape:

```json
{
  "error": {
    "code": "not_found",
    "message": "finding not found",
    "correlation_id": "3f2a…",
    "details": {}
  }
}
```

Branch on `code`. It is part of the v1 contract: adding a code is
additive and safe, changing or removing one is breaking and requires a
version bump. `message` is for humans and may be reworded — never parse
it.

## Codes

| Code | Status | When |
|---|---|---|
| `authentication_error` | 401 | Missing, malformed, expired or badly signed token |
| `authorization_error` | 403 | Authenticated but lacking the required role |
| `not_found` | 404 | Absent, **or** belongs to another tenant |
| `validation_error` | 422 | Malformed body, bad enum, out-of-range paging |
| `invalid_filter` | 422 | Filter combination rejected by the application layer |
| `scan_conflict` | 409 | A scan for this target is already queued or running |
| `scan_failed` | 500 | Reserved |
| `provider_error` | 502 | Reserved: downstream cloud provider failure |
| `rate_limited` | 429 | Reserved: no limiter is implemented yet |
| `service_unavailable` | 503 | Dependency down, or scan submission unconfigured |
| `tenant_isolation_violation` | — | Logged internally; surfaced to clients as `not_found` |
| `internal_error` | 500 | Unexpected. Quote the `correlation_id` |

## Two deliberate opacities

**401 never says why.** Distinguishing "expired" from "bad signature"
from "wrong audience" is a free oracle for an attacker. The specific
reason is logged, not returned.

**404 is indistinguishable across tenants.** A finding belonging to
another tenant returns byte-identical output to a non-existent one. Any
difference would let a caller enumerate other tenants' ids.

## What is never in an error

No stack traces, no SQL, no exception messages from the database or a
cloud provider, no credentials, no JWT contents. An unexpected exception
returns a fixed string and the detail goes to the log, keyed by
correlation id.
