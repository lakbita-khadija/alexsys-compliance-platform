# Authentication Readiness

> Status after STEP 6.5. Supersedes the verdicts in
> `docs/audits/cloud-auth-readiness.md` and
> `docs/audits/core-auth-readiness.md`, which are point-in-time audit
> records and are **not** edited — an audit rewritten once its findings
> are fixed stops being evidence of what was true.

---

## Verdicts

| Area | Before STEP 6.5 | Now |
|---|---|---|
| Tenant ↔ cloud account binding | 🔴 did not exist | ✅ implemented, fails closed |
| AWS STS as an enforcement gate | 🔴 label only | ✅ gate, before collection |
| Azure directory validation | 🔴 parameter that constrained nothing | ✅ from the token's `tid` |
| Azure subscription validation | 🔴 never validated | ✅ validated with its directory |
| `AUTHENTICATION_FAILED` emission | 🔴 declared, never emitted | ✅ emitted on both failure modes |
| AWS `ExternalId` | 🔴 unsupported | ✅ optional, non-disclosing |
| Secret handling | ✅ + one gap | ✅ gap narrowed |
| JWT / RBAC / tenancy | unchanged | unchanged |

All four **P0** findings from the audit are closed. Two of six P1s are
closed; four remain and are listed below.

---

## What changed

**The binding.** `domain/tenants/cloud_accounts.py` introduces
`CloudAccountBinding` (the expectation, from operator configuration) and
`AuthenticatedCloudIdentity` (the observation, from the provider).
`verify_cloud_identity` compares them. An empty binding set permits
nothing — the failure direction that decides whether this is a control at
all.

**The gate.** `VerifyCloudIdentity` runs inside `ScanCloudAccount`
**before** `_collect()`. A test asserts the collector is never called on
a mismatch; rejecting after collection would be theatre, because the
estate would already be in memory tagged with the wrong tenant.

**AWS.** `AwsIdentityProvider` calls `sts:GetCallerIdentity` and raises
on any failure or unparseable response. `AwsCollector._resolve_account_id`
deliberately still swallows failures and returns `None` — same API, two
purposes, opposite correct handling, both documented.

**Azure.** `AzureIdentityProvider` acquires a real ARM token and reads
its `tid`. This replaces `interactive_browser_tenant_id`, which scopes
only the interactive-browser link of the credential chain and was
therefore ignored under every mode a deployed scanner uses. Acquiring the
token eagerly also fixes authentication failures surfacing late and being
blamed on whichever collector ran first.

**Audit.** `AUTHENTICATION_FAILED` finally has a caller, with two
distinguishable reasons (`account_not_bound_to_tenant`,
`identity_unavailable`) so an operator can triage a configuration error
apart from a credential problem.

**ExternalId.** Optional on `AwsCredentialConfig`, passed as an absent
key when unset, `repr=False`, rejected when configured without a
`role_arn` because STS would silently ignore it.

---

## The semantic rule this step protects

```
AccessDenied reading a security group  →  UNKNOWN, the scan continues
Authenticated as the wrong account     →  the scan is rejected
```

Pinned in **both** directions. Reversing either is a serious defect:
treating a denied API call as an identity failure would abort scans over
one unreadable security group; treating an identity failure as resource
uncertainty would silently collect someone else's infrastructure under
this tenant's name.

---

## Verification

```
pytest        1644 passed, 60 skipped, 0 failed     (was 1512 / 60 / 0)
ruff          All checks passed!
mypy          Success: no issues found in 187 source files
```

132 new tests. No test deleted, none weakened.

The 60 skips are the opt-in AWS and Azure integration suites, which
require real credentials. Watch that number: **156 skips means PostgreSQL
is not running** and the persistence suites silently did not execute.

---

## IMPLEMENTED + LOCALLY VERIFIED

- Tenant ↔ cloud account binding, including every fail-closed path
- AWS STS identity gate: correct, wrong, missing binding, missing
  credentials, invalid, expired, STS failure, malformed response
- Azure identity gate: correct, wrong directory, wrong subscription,
  missing binding, credential failure, token failure, undecodable token,
  missing `tid`
- Cross-tenant binding isolation, including the shared-account case that
  requires an explicit binding per tenant
- `AUTHENTICATION_FAILED` emission with tenant, correlation id and
  account — and no secret
- `ExternalId` sent, omitted, never logged, malformed config rejected
- End-to-end scans on both providers: correct identity proceeds, wrong
  identity is rejected **before collection**
- `UNKNOWN` semantics for resource-level `AccessDenied`, unchanged

## ⚠️ REQUIRES LIVE AWS/AZURE VERIFICATION

1. **That a real `DefaultAzureCredential` under managed identity or a
   service principal returns a token whose `tid` is what we expect.** The
   entire Azure fix rests on this and it is asserted against a fake
   token. Highest-value live check.
2. A real cross-account `AssumeRole` with `ExternalId`, and that a wrong
   external id fails as the tests assume.
3. Behaviour of a scan exceeding the assumed-role session lifetime.
4. Real `HttpResponseError` text under 403/429 — the one open question in
   secret redaction.
5. `sts:GetCallerIdentity` under an intentionally minimal-permission role.

---

## Remaining findings

### P0

None. All four are closed.

### P1

| # | Finding | Status |
|---|---|---|
| 5a | `AUTHORIZATION_FAILED` still never emitted | open |
| 5b | `TENANT_ISOLATION_VIOLATION` still never emitted | open |
| 8 | Assumed-role sessions never refreshed — a long scan fails partway, non-retryably | open |
| 10 | No throttling/retry on the Azure path (`resilience.py` is AWS-shaped) | open |
| 6 | No credential verification precedes JWT issuance; Core-as-IdP vs resource-server decision unrecorded | open |

5a and 5b are the natural follow-on: this step wired the *cloud*
authentication event, and the two *application*-layer events have the
same shape of gap. A caller probing another tenant's ids with a valid
token still produces no `audit_events` row.

### P2 / P3

`admin` role gates nothing · no key rotation mechanism · no audit-trail
API · `NoCredentialsError` categorized as a service error · region
validated as non-blank only · no permissions preflight · no unit test
file for `jwt_tokens.py` · no `exp` clock leeway · RBAC enforced at one
layer.

---

## One thing worth knowing about how this went

The first draft of `AzureIdentityProvider` used PyJWT to read the `tid`
claim, and `tests/api/test_architecture.py` failed: exactly one module
may import `jwt`, because a second importer is how a codebase acquires
two token implementations that disagree.

The rule was not widened. The adapter was rewritten to decode base64
directly — which is the better design, because it makes "we are not
verifying anything here" structural rather than a comment. The function
cannot grow into a second verifier; it has no verification library in
scope.
