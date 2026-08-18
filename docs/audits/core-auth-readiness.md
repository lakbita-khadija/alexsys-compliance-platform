# Core Application Authentication Readiness Audit

> **Audit only. No application code was modified.**
>
> Scope: how a **user or service** authenticates to the Core Service and
> how that identity is enforced —
> `user/service → Core → JWT → API → tenant-scoped request`.
>
> This is a different layer from cloud authentication
> (`ComplianceIQ → AWS/Azure`), which is audited in
> [cloud-auth-readiness.md](cloud-auth-readiness.md). The two solve
> different problems and are kept separate throughout.

---

## 1. Verdict up front

| Component | Verdict |
|---|---|
| JWT **verification** | ✅ READY |
| JWT **issuance** | 🟡 PARTIAL — no credential verification precedes it |
| Key management | ✅ READY |
| RBAC | 🟡 PARTIAL — correct where enforced; one role enforces nothing |
| Tenant isolation (API → repository → DB) | ✅ READY |
| Audit trail | 🔴 **NOT READY** for security events |
| Correlation ID | ✅ READY |
| Security test coverage | ✅ READY for verification; 🟡 for issuance |

The verification half of this subsystem is genuinely strong and
adversarially tested. The gaps are on the issuance side and in the audit
trail.

---

## 2. The real flow

```
Expected                        Actual
--------                        ------
User / Service                  ✗ no user model, no service-account store
  ↓                               ↓
Credential verification         ✗ NONE — see §4
  ↓                               ↓
JWT issuance                    JwtTokenIssuer — exists, no HTTP endpoint exposes it
  ↓                               ↓
Claims                          sub, tenant_id, roles, iss, aud, iat, exp ✅
  ↓                               ↓
API validation                  JwtTokenVerifier ✅ strict
  ↓                               ↓
RBAC                            require_role() route dependency ✅
  ↓                               ↓
Tenant-scoped request           identity.tenant_id → repository, tenant-first ✅
```

**Files:** `infrastructure/auth/jwt_tokens.py`,
`application/ports/auth.py`, `presentation/dependencies.py`,
`presentation/routers/meta.py`, `presentation/middleware.py`.

---

## 3. JWT verification — ✅ READY

`JwtTokenVerifier.verify` is the security boundary and it is configured
correctly. Reading the actual `jwt.decode` call rather than trusting
that a library is in use:

```python
jwt.decode(
    raw_token,
    self._public_key,
    algorithms=[ALGORITHM],          # RS256, explicit
    audience=self._settings.audience,
    issuer=self._settings.issuer,
    options={
        "require": ["exp", "iat", "iss", "aud", "sub"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_aud": True,
        "verify_iss": True,
    },
)
```

| Control | Status | Why it holds |
|---|---|---|
| Algorithm restriction | ✅ | `algorithms=[RS256]` passed explicitly — the single line that defeats both `alg=none` and RS256→HS256 confusion |
| `alg=none` | ✅ | Rejected; tested |
| Algorithm confusion | ✅ | Rejected; tested with a **hand-built** HS256 token signed using the public key as the HMAC secret, because PyJWT's encoder refuses to produce one and using it would test the library's politeness instead of our verifier |
| Issuer validation | ✅ | `verify_iss` + explicit issuer; tested |
| Audience validation | ✅ | `verify_aud` + explicit audience; tested |
| Expiration | ✅ | `verify_exp`, `exp` required; tested |
| Required claims | ✅ | `exp, iat, iss, aud, sub` all required |
| Malformed token | ✅ | Catch-all → `AuthenticationError` |
| Missing tenant | ✅ | **Never defaulted.** Explicitly rejected — the one claim that must never fall back to a default |
| Empty tenant | ✅ | Blank string rejected |
| Forged tenant | ✅ | Requires a valid signature; a forged token fails at signature check |
| Forged role | ✅ | Same |
| Non-disclosing 401 | ✅ | A test asserts the body never contains "signature", "expired", "audience", "issuer", "decode" or "algorithm" — distinguishing failure modes hands an attacker a free oracle |

**One deliberate leniency worth naming.** An unrecognized role is
*ignored*, not fatal:

> *"a newer issuer may mint roles this deployment does not know yet, and
> failing closed on the whole token would break rollout. Ignoring is safe
> because an unknown role grants nothing."*

The reasoning is sound — unknown roles are dropped, so the failure mode
is under-privilege, never over-privilege. Worth revisiting only if roles
are ever composed negatively (a "deny" role), which would invert the
safety argument.

**No clock leeway is configured**, so `exp` is enforced to the second.
Correct default; may need a small leeway if issuer and verifier ever run
on hosts with drift.

---

## 4. 🟡 P1 — JWT issuance has no authentication in front of it

`JwtTokenIssuer` exists, mints RS256 tokens, and takes a `TokenRequest`
whose docstring is explicit:

> *"`tenant_id` is supplied by the **issuer's** caller — a trusted,
> server-side path (client-credentials validation) — never by an end user
> asking for a token for an arbitrary tenant."*

The trusted server-side path it refers to **does not exist**. Verified:

- No user model, no service-account model, no credential store.
- No `POST /token`, `/login`, or `/oauth/token` route. Every route in
  `presentation/routers/` is a `GET` except `POST /api/v1/scans`.
- `token_issuer` is referenced in exactly one place in the presentation
  layer: the JWKS endpoint, to publish the **public** key.

So Core **verifies** tokens it never **issues** over HTTP. Tokens are
minted out of band — in tests, and by the stub app for the AI engineer.

This is not a vulnerability today; an unauthenticated issuance endpoint
would be one, and there isn't one. It is a **missing capability**: the
plan's expected flow begins with credential verification, and that step
has no implementation. Whether Core should own it depends on a product
decision not recorded anywhere in the repository — Core as its own IdP,
versus Core as a resource server trusting an external IdP via JWKS. The
verifier already supports the second (it accepts a bare public key, and
a verify-only deployment correctly publishes an empty JWKS key set).

**The decision should be made and written down, because the two answers
imply different work.** Right now the code supports both and commits to
neither.

---

## 5. Key management — ✅ READY

| Question | Answer |
|---|---|
| Signing algorithm | RS256 |
| Where is the private key? | In `RsaKeyPair`, in memory. **Never rendered** — no `__repr__`, no `__str__`, no PEM-returning property. Only the public half is exportable, and only as JWKS. *"A key object that can print itself ends up in a traceback eventually."* |
| Public key distribution | `GET /.well-known/jwks.json`, unauthenticated by design |
| Private material in JWKS? | No. A test asserts the key set is exactly `{kty, use, alg, kid, n, e}` and that none of `d, p, q, dp, dq, qi` appears |
| Key rotation | 🟡 `kid` is present (`core-1`), so rotation is *representable*. No rotation mechanism, and JWKS publishes exactly one key, so a rolling rotation would break verification mid-flight |

---

## 6. RBAC — 🟡 PARTIAL

The actual role vocabulary, not an invented one:

| Role | Meaning | Enforced at |
|---|---|---|
| `reader` | Read findings, scores, scans, attack paths | Every `/api/v1` read, via `identity.require_role(Role.READER)` in each use case |
| `scanner` | Trigger a scan — *"starting a scan spends real money and hits real cloud APIs"* | `POST /api/v1/scans` |
| `admin` | Administrative operations | 🔴 **Nothing. No endpoint requires it** — the enum comments say "Reserved" |

**Enforcement depth is correct.** RBAC is applied in the **use case**
(`identity.require_role(...)` inside `QueryFindingsPage`,
`QueryAttackPathsForScan`, etc.), not only as a route decorator. A new
route that forgets its dependency still cannot bypass the check, because
the use case underneath performs it. `require_role()` also exists as a
route dependency so the requirement appears in the generated OpenAPI.

**No implicit inheritance.** A test asserts `admin` does **not** imply
`reader`. That is the right default: implicit inheritance is how an
"admin" quietly acquires a capability nobody granted.

**Gaps:**

- `admin` grants nothing and gates nothing. Either wire it or document
  it as reserved in the API contract, so an operator does not assume
  issuing an admin token confers administrative access.
- No repository-level role enforcement. Repositories enforce *tenant*,
  not *role*. Defensible — roles are a use-case concern — but it means
  role enforcement has exactly one layer, whereas tenant has three.

---

## 7. Tenant isolation — ✅ READY

Verified at every layer the plan names.

| Layer | Mechanism | Evidence |
|---|---|---|
| JWT | `tenant_id` required, never defaulted | §3 |
| API | **No `tenant_id` parameter exists anywhere.** Tenant comes only from the verified token | Route signatures |
| Application | Use cases pass `identity.tenant_id`, never a caller value | `query_attack_paths.py`, `query_finding_pages.py` |
| Repository | Every query filters tenant-first | `scan_repository.py` |
| PostgreSQL | Every non-unique index leads with `tenant_id`; asserted by a migration test that walks the live schema | `test_migrations.py` |
| Resource Graph | `BuildResourceGraph` raises `TenantIsolationViolation` on a foreign resource | `domain/tenants/isolation.py` |
| Findings | Foreign id → 404 | `test_security.py` |
| Attack paths | Foreign id → 404, ids differing only by tenant prefix | `test_attack_paths.py` |

### The five scenarios, as executed

| Test | Scenario | Result |
|---|---|---|
| **A** | Tenant A requests tenant B's finding | ✅ 404. And a foreign finding is **byte-identical** to a nonexistent one (modulo correlation id) — any difference would be an enumeration oracle |
| **B** | Tenant A requests tenant B's attack path | ✅ 404, same non-disclosure property. Tested with an id differing from A's only by prefix, so a missing filter surfaces as a leak rather than an empty result |
| **C** | Tenant A retrieves tenant B graph nodes | ✅ Impossible by construction — the graph is per-scan, in-memory, tenant-scoped at build, and a foreign resource raises |
| **D** | Valid token, manipulated body `tenant_id` | ✅ Rejected — `test_a_client_supplied_tenant_id_is_rejected` |
| **E** | Valid token, malicious query parameters | ✅ Ignored — `?tenant_id=globex` on both findings and attack paths returns only `acme` rows |

**The one caveat, and it is not in this layer.** All of the above
protects data *already attributed* to a tenant. Attribution happens at
collection time, and there is no tenant↔cloud-account binding to make it
verifiable — see [cloud-auth-readiness.md](cloud-auth-readiness.md) §4.
Isolation here is sound; what enters the boundary is not validated.

---

## 8. 🔴 P1 — the audit trail does not record security events

`AuditAction` declares thirteen actions. Three are security events:

```
AUTHENTICATION_FAILED
AUTHORIZATION_FAILED
TENANT_ISOLATION_VIOLATION
```

**None of the three is ever emitted.** Verified across the whole
repository — the only occurrences are the enum definitions themselves
and a same-named string in `presentation/errors.py`, which is an HTTP
error code, not an audit record.

The only code that records audit events is `application/scanning/submit_scan.py`
(3 call sites: scan submitted, completed, failed).

So an attacker probing tenant B's finding ids with a valid tenant A
token generates **no audit record at all**. The 404s appear in the
request log — which carries correlation id, tenant, subject, method,
path, status — but nothing in `audit_events`, the table a security
reviewer would query.

The event schema itself is complete and correct (actor, tenant,
timestamp, action, result, correlation id), and `AuditEvent` is a closed
vocabulary. This is purely a matter of nothing calling it on the paths
that matter.

**Also:** no API exposes `audit_events`. The table is written and read
only by repository code. An auditor cannot retrieve the trail through
the product.

Secrets in audit records: ✅ none. `AuditEvent` has no token or
credential field, and the recorder stores subject and tenant, never the
token.

---

## 9. Correlation ID — ✅ READY

`CorrelationIdMiddleware`:

- Accepts `X-Correlation-ID` from the client
- **Sanitizes it**: max length enforced, and only printable non-space
  ASCII (33–126) accepted — explicitly so a newline cannot inject a
  forged log record. That is log-injection defence most implementations
  skip
- Generates a UUID4 when absent or rejected
- Echoes it on every response, including errors
- Propagates it into logs, error envelopes and audit records
- **Is never used as identity.** Tenant and subject come from the
  verified token; the correlation id appears alongside them and never
  in place of them

---

## 10. Test coverage — measured, not assumed

| Component | Code | Unit tests | Integration | Security tests | Production ready |
|---|---|---|---|---|---|
| JWT issuance | YES | **NO dedicated file** | via API suite | PARTIAL | 🟡 |
| JWT verification | YES | **NO dedicated file** | YES | **YES — 32 tests** | ✅ |
| Key management / JWKS | YES | NO | YES | YES | ✅ |
| RBAC | YES | NO | YES | YES (4) | 🟡 |
| Tenant isolation | YES | YES | YES (real Postgres) | YES (many) | ✅ |
| Audit — scan lifecycle | YES | YES | YES | NO | 🟡 |
| Audit — security events | **NO CODE** | ➖ | ➖ | ➖ | 🔴 |
| Correlation ID | YES | NO | YES | PARTIAL | ✅ |

**Note on "NO dedicated file".** `infrastructure/auth/jwt_tokens.py` has
no `tests/unit/infrastructure/test_jwt_tokens.py`. Its coverage comes
entirely from `tests/api/test_security.py` (32 adversarial tests through
the real app). That is *better* coverage than a unit file would give for
the security properties — it tests the verifier as wired, not in
isolation — but it means a change to the issuer's claim construction has
no fast unit-level guard.

---

## 11. Findings by priority

### P1

1. **Security audit events are declared but never emitted** (§8). No
   record of failed authentication, failed authorization, or tenant
   isolation violation.
2. **No credential verification precedes token issuance** (§4). The
   "trusted server-side path" the issuer's docstring assumes does not
   exist, and the Core-as-IdP vs Core-as-resource-server decision is
   unrecorded.

### P2

3. **`admin` role gates nothing** (§6) — reserved but undocumented in
   the API contract.
4. **No key rotation mechanism** (§5) — `kid` exists, JWKS publishes one
   key, rolling rotation would break verification mid-flight.
5. **No API exposes the audit trail** (§8).
6. **No unit test file for `jwt_tokens.py`** (§10).

### P3

7. No clock leeway on `exp` (§3) — correct today, may matter with drift.
8. RBAC is enforced at one layer (use case); tenant is enforced at three.

---

## 12. Classification summary

```
JWT issuance:     🟡 PARTIAL   — implemented, unexposed, no auth in front
JWT verification: ✅ READY     — strict, adversarially tested
RBAC:             🟡 PARTIAL   — sound where enforced; `admin` inert
Tenancy:          ✅ READY     — enforced and tested at every layer
Audit:            🔴 NOT READY — security events declared, never emitted
```
