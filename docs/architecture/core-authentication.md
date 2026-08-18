# Core Application Authentication

> How a **user or service** authenticates to the Core Service, and how
> that identity is enforced.
>
> Distinct from [cloud-authentication.md](cloud-authentication.md), which
> covers `ComplianceIQ → AWS/Azure`. Same word, different problem: this
> layer decides *who may ask us questions*, that one decides *whose
> infrastructure we are allowed to look at*.

---

## 1. The flow

```
User / Service
  ↓
credential verification        ← NOT IMPLEMENTED — see §5
  ↓
JwtTokenIssuer                 RS256, kid=core-1
  ↓
claims: sub · tenant_id · roles · iss · aud · iat · exp
  ↓
JwtTokenVerifier               signature · algorithm · issuer · audience · expiry
  ↓
AuthenticatedIdentity          obtainable ONLY from a verifier
  ↓
require_role(...)              route dependency + use-case enforcement
  ↓
tenant-scoped repository query tenant-first WHERE clause, always
```

---

## 2. Verification

`infrastructure/auth/jwt_tokens.py` is the security boundary, and the
`jwt.decode` call is configured explicitly rather than by default:

```python
algorithms=[ALGORITHM],                    # RS256 — one line, two attacks defeated
audience=self._settings.audience,
issuer=self._settings.issuer,
options={
    "require": ["exp", "iat", "iss", "aud", "sub"],
    "verify_signature": True,
    "verify_exp": True,
    "verify_aud": True,
    "verify_iss": True,
}
```

`algorithms=[RS256]` is what defeats both `alg=none` and the RS256→HS256
confusion attack, where an attacker signs with HS256 using the public key
— which is not secret — as the HMAC secret.

**`tenant_id` is never defaulted.** A token without it is rejected
outright. Defaulting the one security-critical claim is a cross-tenant
read waiting to happen.

**An unrecognized role is ignored, not fatal.** A newer issuer may mint
roles this deployment does not know, and failing closed on the whole
token would break rollout. Safe because an unknown role grants nothing —
the failure mode is under-privilege, never over-privilege. Worth
revisiting only if roles are ever composed negatively.

**A 401 never says why.** Distinguishing "expired" from "bad signature"
from "wrong audience" hands an attacker a free oracle. A test asserts the
body contains none of *signature, expired, audience, issuer, decode,
algorithm*.

### Adversarially tested

`alg=none` · RS256→HS256 confusion (with a **hand-built** token, because
PyJWT refuses to encode one and using its encoder would test the
library's politeness rather than our verifier) · wrong issuer · wrong
audience · expired · missing `tenant_id` · blank `tenant_id` · forged
signature · malformed token · missing required claims.

### Only one module knows what a JWT is

`tests/api/test_architecture.py` asserts that exactly one file imports
`jwt`. A second importer is how a service ends up with one path that
checks the audience and one that does not.

This is why `infrastructure/cloud/azure/identity.py` — which reads a
`tid` claim out of an Entra token — decodes base64 by hand instead. It is
not verifying anything, and giving it a verification library in scope
would let it grow into a second verifier. See
[cloud-authentication.md](cloud-authentication.md) §5.

---

## 3. Key management

| | |
|---|---|
| Algorithm | RS256 |
| Private key | In `RsaKeyPair`, in memory. **Never rendered** — no `__repr__`, no `__str__`, no PEM-returning property. *A key object that can print itself ends up in a traceback eventually.* |
| Public key | `GET /.well-known/jwks.json`, unauthenticated by design |
| JWKS contents | Exactly `{kty, use, alg, kid, n, e}`. A test asserts none of `d, p, q, dp, dq, qi` appears |
| Rotation | 🟡 `kid` is present so rotation is representable; there is no rotation mechanism and JWKS publishes one key |

A verify-only deployment holds no signing key and correctly publishes an
empty key set rather than erroring.

---

## 4. RBAC

The actual vocabulary — three roles, closed:

| Role | Grants | Enforced |
|---|---|---|
| `reader` | findings, scores, scans, attack paths | every `/api/v1` read |
| `scanner` | trigger a scan — *"starting a scan spends real money and hits real cloud APIs"* | `POST /api/v1/scans` |
| `admin` | administrative operations | 🔴 **nothing requires it yet** |

**Enforcement is in the use case**, not only the route. A new route that
forgets its dependency still cannot bypass the check, because
`identity.require_role(...)` runs underneath. `require_role()` also
exists as a route dependency so the requirement appears in the generated
OpenAPI.

**No implicit inheritance.** `admin` does not imply `reader`; a test
pins it. Implicit inheritance is how an "admin" quietly acquires a
capability nobody granted.

---

## 5. 🟡 Issuance has no authentication in front of it

`JwtTokenIssuer` exists and mints tokens. `TokenRequest`'s docstring is
explicit that `tenant_id` comes from "a trusted, server-side path
(client-credentials validation)".

**That path does not exist.** There is no user model, no service-account
store, and no `POST /token` route — every route is a `GET` except
`POST /api/v1/scans`. `token_issuer` is referenced once in the
presentation layer, by the JWKS endpoint, to publish the *public* key.

Core therefore **verifies** tokens it never **issues** over HTTP. Tokens
are minted out of band — in tests, and by the stub app for the AI
engineer.

This is not a vulnerability; an unauthenticated issuance endpoint would
be one, and there isn't one. It is a missing capability, and the decision
behind it is unrecorded: **Core as its own IdP** versus **Core as a
resource server trusting an external IdP via JWKS**. The verifier already
supports the second — it accepts a bare public key. The code supports
both and commits to neither, and that choice should be written down
because the two answers imply different work.

---

## 6. Tenant isolation

Enforced at every layer, not one:

| Layer | Mechanism |
|---|---|
| JWT | `tenant_id` required, never defaulted |
| API | **No `tenant_id` parameter exists anywhere.** A structural test asserts no route handler declares one |
| Application | Use cases pass `identity.tenant_id`, never a caller value |
| Repository | Every query filters tenant-first |
| PostgreSQL | Every non-unique index leads with `tenant_id`, asserted against the live schema |
| Graph | `BuildResourceGraph` raises `TenantIsolationViolation` on a foreign resource |

Verified scenarios: a foreign finding and a nonexistent one return
**identical** 404 bodies (any difference is an enumeration oracle); the
same for attack paths, tested with ids differing only by tenant prefix; a
body-supplied `tenant_id` is rejected; a query-parameter `tenant_id` is
ignored.

> **The upstream caveat.** All of this protects data *already attributed*
> to a tenant. Attribution happens at collection time, and until STEP 6.5
> there was nothing making it verifiable. See
> [cloud-authentication.md](cloud-authentication.md).

---

## 7. Audit trail

`AuditAction` is a closed vocabulary. Its three security events —
`AUTHENTICATION_FAILED`, `AUTHORIZATION_FAILED`,
`TENANT_ISOLATION_VIOLATION` — were declared in Phase 5 and emitted by
nothing.

**As of STEP 6.5, `AUTHENTICATION_FAILED` has a caller**: the cloud
identity gate emits it on both a binding mismatch and an unresolvable
identity, with tenant, correlation id, provider, reason and the account
we authenticated as.

`AUTHORIZATION_FAILED` and `TENANT_ISOLATION_VIOLATION` remain
**unemitted**. A caller probing another tenant's finding ids with a valid
token still produces no `audit_events` row — the 404s appear in the
request log, but not in the table a security reviewer queries. That is an
open P1.

No API exposes `audit_events`; the table is written and read only by
repository code.

Secrets never reach it. `AuditEvent` rejects credential-shaped metadata
keys outright rather than redacting — unlike collected cloud evidence,
this data is written by code we control, so a suspicious key is a bug and
should fail loudly.

---

## 8. Correlation ID

`X-Correlation-ID` is accepted, **sanitized** (bounded length, printable
non-space ASCII only — so a newline cannot inject a forged log record),
generated when absent, echoed on every response including errors, and
propagated into logs, error envelopes and audit records.

It is **never** identity. Tenant and subject come from the verified
token; the correlation id sits alongside them and never in place of them.

---

## 9. Status

| Component | Status |
|---|---|
| JWT verification | ✅ READY |
| JWT issuance | 🟡 PARTIAL — no credential verification precedes it |
| Key management | ✅ READY (no rotation mechanism) |
| RBAC | 🟡 PARTIAL — sound where enforced; `admin` inert |
| Tenant isolation | ✅ READY |
| Audit — authentication | 🟡 PARTIAL — cloud identity emits; app-layer authz does not |
| Correlation ID | ✅ READY |

This layer needs no live cloud verification: it is exercised through the
real FastAPI app over in-memory adapters, with routing, authentication,
tenant scoping and error handling all real.
