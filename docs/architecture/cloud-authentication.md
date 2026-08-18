# Cloud Authentication

> How ComplianceIQ authenticates **to AWS and Azure** in order to collect
> resources. This is the `ComplianceIQ → cloud provider` direction.
>
> The other authentication layer — `user/service → Core → JWT → API` —
> is a different problem with different failure modes and lives in
> [core-authentication.md](core-authentication.md). The two are never
> merged, in the code or here.

---

## 1. The flows

### AWS

```
Tenant
  ↓
CloudAccountBinding            authoritative config: which accounts this tenant owns
  ↓
AwsCredentialConfig            region · profile? · role_arn? · external_id?
  ↓
boto3 default credential chain env · shared file · instance role
  ↓
AwsSessionFactory              + sts:AssumeRole (ExternalId when configured)
  ↓
sts:GetCallerIdentity          ← THE GATE, not a label
  ↓
verify_cloud_identity          authenticated account == a bound account?
  ↓                                         ↓ no
Collectors                          CloudIdentityMismatch — scan rejected,
  ↓                                  AUTHENTICATION_FAILED recorded
Scan
```

### Azure

```
Tenant
  ↓
CloudAccountBinding            subscription id + Entra directory id (both required)
  ↓
AzureCredentialConfig          subscription_id · tenant_id? · resource_group?
  ↓
DefaultAzureCredential         env · managed identity · workload identity · az login
  ↓
credential.get_token(ARM)      ← forces the chain to resolve NOW
  ↓
token `tid` claim              ← the authenticated directory
  ↓
verify_cloud_identity          directory AND subscription bound to this tenant?
  ↓                                         ↓ no
Collectors                          CloudIdentityMismatch — scan rejected
  ↓
Scan
```

---

## 2. The defect this replaced

`sts:GetCallerIdentity` **was** already being called before STEP 6.5. The
problem was never that we failed to ask; it was that we discarded the
answer's authority. The account id became a descriptive label on every
`NormalizedResource` and was compared against nothing, because there was
nothing to compare it to: `Tenant` was `(id, name)` and no store recorded
which accounts a tenant owned.

The consequence, stated plainly: point tenant A's scan at credentials for
account B and the scan succeeded. Account B's entire estate was
collected, graphed, scored and served as tenant A's data. Every
downstream isolation control — and they are genuinely strong — then
protected the wrong data perfectly.

**Tenant isolation in the database is only as good as tenant attribution
at ingest.** Attribution was asserted by configuration and never
verified.

Azure was worse in one respect. It asked nothing at all, passed its
configured directory as
`DefaultAzureCredential(interactive_browser_tenant_id=...)` — which
scopes **only** the interactive-browser link of the chain, and is
therefore ignored under managed identity, workload identity or an
environment service principal — and carried a comment asserting no
identity round trip was needed. The AWS code made no claim; the Azure
code looked like a control and was not one.

---

## 3. The binding

`domain/tenants/cloud_accounts.py`.

```python
CloudAccountBinding(
    tenant_id=TenantId("acme"),
    provider=CloudProvider.AWS,
    account_id="111111111111",
    directory_id=None,          # required for Azure
)
```

Two ideas, deliberately not collapsed into one:

| | What it is | Where it comes from |
|---|---|---|
| `CloudAccountBinding` | the **expectation** | operator configuration |
| `AuthenticatedCloudIdentity` | the **observation** | the provider, over the network |

`verify_cloud_identity(tenant_id, actual, bindings)` compares them and
returns the authorizing binding or raises `CloudIdentityMismatch`.

### Three decisions worth the words

**An empty binding set permits nothing.** A tenant with no configured
bindings is refused, not waved through. Reading "no bindings" as "no
restriction" would make the whole mechanism fail open, and a control that
fails open on missing configuration is worse than no control because it
looks like one.

**An Azure binding must name its directory.** A subscription id alone
cannot establish which directory authenticated, and a subscription can be
moved between directories. A binding that cannot answer the question it
exists to answer is rejected at construction.

**Sharing an account across tenants requires an explicit binding for
each.** It is legitimate — an MSP scanning for a subsidiary — and it
never happens implicitly.

### Configuration

`COMPLIANCEIQ_CLOUD_ACCOUNT_BINDINGS`, a JSON array:

```json
[
  {"tenant_id": "acme", "provider": "aws",   "account_id": "111111111111"},
  {"tenant_id": "acme", "provider": "azure", "account_id": "sub-1",
                                             "directory_id": "dir-1"}
]
```

Parsed at startup and validated by `CloudAccountBinding`'s own
constructor, so a malformed entry fails the deploy rather than the first
scan of the night. Adapters are **read-only**: nothing in the running
application can add a binding, because a control the application can
widen is a control an application bug can widen.

There is no PostgreSQL-backed adapter. That is a considered gap: a table
for this is only worth having alongside a tenant-administration API to
manage it, an audit trail for binding changes, and a migration path for
existing deployments — none of which exists yet. Environment
configuration is honest about being operator-owned in the meantime.

---

## 4. The gate

`application/scanning/verify_cloud_identity.py`, run by
`ScanCloudAccount` **before** `_collect()`.

The ordering is the control. Once resources exist in memory tagged with
the requesting tenant, the misattribution has already happened and every
later check is checking the wrong thing. A test asserts the collector is
never called on a mismatch — rejecting after collection would be theatre.

### The distinction that must never be reversed

```
AccessDenied reading a security group  →  UNKNOWN, the scan continues
Authenticated as the wrong account     →  the scan is rejected
```

The first is uncertainty about one resource, and the three-valued logic
exists to carry it honestly. The second means we are looking at the wrong
estate; degrading it to `UNKNOWN` would silently collect someone else's
infrastructure under this tenant's name.

Both directions are pinned by tests, because either reversal is a serious
defect: treating a denied API call as an identity failure would abort
scans over a single unreadable security group.

### Two failure modes, recorded separately

| Exception | Meaning | Operator action |
|---|---|---|
| `CloudIdentityMismatch` | the provider told us who we are, and it is the wrong account | fix the binding or the credentials |
| `CloudAuthenticationFailure` | the provider would not tell us — missing, invalid, expired, unreachable, unparseable | fix the credential |

The second subclasses the first, so a caller wanting "abort on any
identity problem" catches one exception while a caller that triages them
separately still can.

---

## 5. Where each side of the comparison comes from

### AWS — `infrastructure/cloud/aws/identity.py`

`AwsIdentityProvider` calls `sts:GetCallerIdentity` and **raises** on any
failure or on a response it cannot parse.

Note that `AwsCollector._resolve_account_id` still exists and still
swallows STS failures, returning `None`. That is not a leftover. The two
call sites ask the same API for different purposes and must handle
failure oppositely:

- `_resolve_account_id` produces an **additive label** on resources; a
  denied call should degrade the label, not abort the scan.
- `AwsIdentityProvider` produces the **gate**; not knowing which account
  we authenticated to is a reason to refuse to collect.

`GetCallerIdentity` requires no IAM permission and cannot be denied by
policy, so a failure there is a genuine credential or connectivity
problem rather than an under-privileged role.

### Azure — `infrastructure/cloud/azure/identity.py`

Azure has no `GetCallerIdentity`. The authoritative answer is the access
token: an Entra-issued JWT whose `tid` claim names the directory that
authenticated. Acquiring one via `get_token(ARM_SCOPE)` also forces the
credential chain to resolve immediately, which fixes the separate problem
of authentication failures surfacing late and being attributed to
whichever collector ran first.

**On reading a token without verifying its signature.** We do, and it is
safe *here* for a reason worth stating rather than assuming: this token
is not an untrusted input. We just obtained it ourselves, over TLS, from
the SDK, and we are not authorizing anyone with it — we are reading which
directory our own credential belongs to. Verifying would require Entra's
JWKS and would defend only against an attacker who already controls our
SDK's network responses, at which point the scan is compromised anyway.
The claim feeds a check that fails closed.

The payload is decoded with `base64`, **not** PyJWT. That is
architectural: `tests/api/test_architecture.py` asserts exactly one
module imports `jwt`, because a second importer is how a codebase
acquires two token implementations that disagree — one that checks the
audience and one that does not. Using base64 makes "we are not verifying"
structural: the function cannot grow into a second verifier because it
has no verification library in scope.

Real verification lives in `infrastructure/auth/jwt_tokens.py` and stays
the only place that word applies. Same file format, opposite trust
posture; the difference is who produced the token.

`interactive_browser_tenant_id` is still passed, because it genuinely
helps the local `az login` path. It is documented in the code as **not**
the tenant control. The parameter stays; the false claim does not.

---

## 6. AssumeRole and `ExternalId`

`AwsCredentialConfig.external_id`, optional, used when `role_arn` is set.

The standard defence against the confused-deputy problem for a SaaS
scanner: a customer's cross-account role carries an `sts:ExternalId`
condition, so knowing the role ARN — which is not secret and is visible
in their own console — is not enough for another customer of the same
vendor to assume it. Before this, a customer could not configure that
protection even if they wanted to.

- Absent by default; existing single-account paths are byte-identical.
- Built as an **absent key**, not `ExternalId=None`: botocore validates
  parameter types and rejects an explicit None.
- `repr=False` on the field. It is not a credential — AWS documents it as
  not secret — but it is an access-control input, and a config object
  that prints it ends up in a traceback, then a log, then a ticket.
- An `external_id` without a `role_arn` is **rejected at construction**.
  STS consults it during `AssumeRole` and nowhere else, so that
  configuration would silently do nothing while an operator believed a
  control was active.
- An `AccessDenied` from a wrong external id does not echo the value that
  was tried.

---

## 7. Secret handling

Neither credential config models a secret. `AwsCredentialConfig` has no
access key fields; `AzureCredentialConfig` has no client secret. A secret
that is never modelled cannot be logged, serialized, committed or leaked
through a `__repr__`.

Beyond that:

| Surface | Guarantee |
|---|---|
| Audit metadata | The exception **type** is recorded, never its message — SDK messages can embed request URLs, and an Azure SAS-style URL carries its credential in the query string |
| `AuditEvent` | Rejects credential-shaped metadata keys **outright** rather than redacting, so a mistake fails loudly |
| Raised errors | `CloudAuthenticationFailure` names the exception type, not the underlying text |
| Azure token | Never appears in an identity object or a decode error |
| Findings / resources / graph / attack paths / DB | `redact()` at the persistence boundary, tested against a real database |

Account identifiers **are** recorded, deliberately: an AWS account id
appears in every ARN and a subscription id in every Azure resource id.
They are not secrets, and an operator cannot fix a mismatch without them.

---

## 8. What is verified locally, and what is not

### Locally verified (fakes, mocks, no cloud account)

- The binding model, including every fail-closed path
- The STS gate: correct account, wrong account, missing binding, missing
  credentials, invalid credentials, expired credentials, STS failure,
  malformed STS response
- Azure: correct directory, wrong directory, wrong subscription, missing
  binding, credential failure, token acquisition failure, undecodable
  token, missing `tid`
- Cross-tenant isolation of bindings
- `AUTHENTICATION_FAILED` emission, its metadata, its correlation id, and
  that no secret rides along
- `ExternalId` presence, absence, non-disclosure, and rejection of
  malformed configuration
- End-to-end: correct identity scans, wrong identity is rejected **before
  collection**, `UNKNOWN` semantics unchanged

### ⚠️ Requires live verification

No cloud authentication code in this repository has executed against a
real AWS account or Azure subscription. Specifically unproven:

1. That `DefaultAzureCredential` under a **real** managed identity or
   service principal returns a token whose `tid` is what we expect. The
   whole Azure fix rests on this and it is asserted against a fake token.
2. That a real cross-account `AssumeRole` with `ExternalId` succeeds, and
   that a wrong external id fails the way the tests assume.
3. Behaviour of a scan exceeding the assumed-role session lifetime —
   sessions are still minted once per scan and never refreshed (P1, open).
4. The actual text and shape of `HttpResponseError` under 403/429, which
   is what would settle whether raw SDK message text can carry a
   credential.
5. That `sts:GetCallerIdentity` behaves as assumed under an
   intentionally minimal-permission role.
