# Cloud Authentication Readiness Audit

> **Audit only. No application code was modified.**
>
> Scope: how ComplianceIQ authenticates **to AWS and Azure** in order to
> collect resources. This is the `ComplianceIQ → cloud provider`
> direction and nothing else. Application authentication
> (`user/service → Core → JWT → API`) is a different layer with
> different failure modes and is audited separately in
> [core-auth-readiness.md](core-auth-readiness.md). The two are never
> conflated here.
>
> Every classification below was obtained by reading the current code or
> executing against it. Prior reports were treated as unverified claims.

---

## 1. Verdict up front

| Layer | Verdict |
|---|---|
| AWS credential handling (secrets never modeled) | ✅ READY |
| AWS session construction | 🟡 PARTIAL — ⚠️ needs live verification |
| AWS account identity **validation** | 🔴 **NOT READY** — discovered, never checked |
| Azure credential handling | ✅ READY |
| Azure client construction | 🟡 PARTIAL — ⚠️ needs live verification |
| Azure tenant / subscription **validation** | 🔴 **NOT READY** — neither is validated |
| Tenant ↔ cloud account binding | 🔴 **NOT READY** — no such binding exists |
| Secret redaction | ✅ READY |
| Production wiring of a real scan | 🔴 **NOT WIRED** — deliberate, and visible |

Nothing in this audit has ever run against a real AWS account or Azure
subscription in this repository. Every classification marked
⚠️ is *code-correct against fakes modelled on documented response
shapes* and unproven against the real thing.

---

## 2. The AWS flow, as it actually is

The plan's expected flow and the real one diverge at one step.

```
Expected                          Actual
--------                          ------
Tenant                            (no tenant→account binding exists)
  ↓                                 ↓
Credential reference              AwsCredentialConfig(region, profile?, role_arn?)
  ↓                                 ↓
Credential loading                boto3 default chain (env / shared file / instance role)
  ↓                                 ↓
boto3 Session                     AwsSessionFactory.create()
  ↓                                 ↓
STS identity VALIDATION           sts:GetCallerIdentity → used as a LABEL, never compared
  ↓                                 ↓
AWS account identity              account_id: str | None on every resource
  ↓                                 ↓
AWS clients                       session.client(...) per sub-collector
  ↓                                 ↓
Collectors                        8 registered in AwsCollector
  ↓                                 ↓
Scan                              ScanCloudAccount  ← reachable only from a dev script
```

**Files:** `infrastructure/cloud/aws/credentials.py` (36 lines),
`session.py` (56), `collector.py`, `errors.py`.

### 2.1 Credentials — the strongest part of this subsystem

`AwsCredentialConfig` holds `region`, `profile`, `role_arn`. It has **no
field** for `aws_access_key_id`, `aws_secret_access_key`, or
`aws_session_token`.

This is the right design and it is worth naming why: a secret that is
never modelled cannot be logged, serialized, committed, persisted, or
leaked through a `__repr__`. The class is a *strategy pointer* — "here
is how to obtain a session" — not a credential carrier. Authentication
resolves through boto3's own default chain.

Verified by a test that asserts the dataclass has no such fields
(`test_aws_session.py::test_config_never_carries_raw_access_keys`) and
another that asserts assumed-role temporary credentials never appear in
a config `repr`.

| Question | Answer |
|---|---|
| Where are credentials stored? | Nowhere in this codebase. boto3's chain resolves them. |
| Are raw credentials ever persisted? | No. No field can hold one. |
| Passed by reference? | Yes — profile name / role ARN only. |
| From environment variables? | Yes, via boto3's chain. |
| From a secrets manager? | **No integration exists.** |
| Standard credential abstraction? | Yes — `AwsCredentialConfig`. |
| Rotation supported? | **Implicitly, not explicitly.** Rotation happens outside the process (instance role, env refresh). Assumed-role sessions are minted once per scan and never refreshed — see §2.4. |

### 2.2 Session construction

```python
base_session = boto3.Session(profile_name=config.profile, region_name=config.region)
if config.role_arn is None:
    return base_session
return self._assume_role(base_session, config)
```

Role assumption uses `sts:AssumeRole` with a fixed session name
(`complianceiq-scan`). `ClientError` is translated through
`translate_client_error`, which maps AWS error codes to
`AwsAuthenticationError` / `AwsPermissionError` / `AwsServiceError`.

**Not supported:** external ID, MFA serial, session duration, session
policy, session tagging.

The missing **external ID** is worth calling out on its own. The
standard pattern for a SaaS CSPM scanning a customer account is a
cross-account role with an `sts:ExternalId` condition, precisely to
prevent the confused-deputy attack where another customer of the same
vendor guesses the role ARN. `AssumeRole` here passes no `ExternalId`,
so a customer *cannot* configure that protection even if they want it.
This is P1, not P0, only because no customer is onboarded yet.

### 2.3 🔴 P0 — the account is identified but never validated

```python
def _resolve_account_id(session):
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except Exception:
        logger.warning(...)
        return None
```

`sts:GetCallerIdentity` **is** called. What is missing is the
comparison. The returned account id is threaded into every
`NormalizedResource.account_id` as a **descriptive label**. It is never
checked against anything, because there is nothing to check it against
(§4).

The consequence, stated plainly: **if an operator points tenant A's scan
at credentials for account B, the scan succeeds and every resource in
account B is stored, graphed, scored and served as tenant A's data.**
Nothing detects it. The tenant filter on every repository query is
airtight (§6 of the core audit) — and entirely beside the point, because
the wrong data was correctly labelled with the right tenant at
collection time.

That is the single most important finding in this audit. Tenant
isolation in the database is only as good as the tenant attribution at
ingest, and attribution here is asserted by configuration, never
verified.

Secondary issue in the same function: `except Exception` is bare and
non-fatal by design (documented in the module docstring), so a denied
`sts:GetCallerIdentity` degrades to `account_id=None` on every resource
rather than aborting. That is defensible — but it means the scan cannot
distinguish "we could not identify the account" from "the account is the
right one", which is exactly the distinction a validation step would
need.

### 2.4 Credential rotation and long scans

An assumed-role session is created once, at collector construction, and
reused for the whole scan. `AssumeRole` defaults to a 1-hour session.

A scan of a large estate that exceeds the session lifetime will begin
failing mid-collection with `ExpiredToken`. The resilience layer
(`infrastructure/cloud/resilience.py`) retries throttling, but an
expired token is not a retryable condition — retrying it produces the
same error until the session is rebuilt, which nothing does.

**Classification: NOT HANDLED.** Untested and, on current evidence,
unhandled. Whether it bites depends on estate size, which is exactly why
it needs live verification rather than reasoning.

### 2.5 AWS failure-case matrix

| # | Case | Classification | Evidence |
|---|---|---|---|
| 1 | Missing credentials | 🟡 PARTIALLY HANDLED | boto3 raises `NoCredentialsError`; it is **not** in `translate_client_error`'s mapped set, so it surfaces as `AwsServiceError` — a wrong category for an auth failure |
| 2 | Invalid credentials | ✅ HANDLED | `InvalidClientTokenId` / `UnrecognizedClientException` → `AwsAuthenticationError` |
| 3 | Expired credentials | 🟡 PARTIALLY HANDLED | Translated correctly if raised; **never refreshed** (§2.4) |
| 4 | Wrong AWS account | 🔴 **NOT HANDLED** | §2.3 — no comparison exists |
| 5 | AccessDenied | ✅ HANDLED | → `AwsPermissionError`; per-collector, scan continues; `UNKNOWN` recorded where the distinction matters (e.g. `instance_profile_role_arn`) |
| 6 | Throttling | ✅ HANDLED | `resilience.py`, full-jitter exponential backoff |
| 7 | Network/API failure | ✅ HANDLED | → `AwsServiceError`, retried where retryable |
| 8 | Partial permissions | ✅ HANDLED | `AwsCollector.collect()` accumulates failures; raises only if **all** collectors fail |
| 9 | Role assumption failure | ✅ HANDLED | `translate_client_error(context="assuming role …")` |
| 10 | Region misconfiguration | 🟡 PARTIALLY HANDLED | Region is validated as non-blank, never as a real AWS region. A typo yields an endpoint resolution error surfaced as `AwsServiceError` |

**On "partial permissions is HANDLED":** it is handled in the sense that
the scan survives and the failure is structured (`ScanError` carries
provider, service, operation, error code, retryability). It is *not*
handled in the sense of an operator-facing permissions preflight — there
is no "here is what this role cannot see" report before a scan runs.

---

## 3. The Azure flow, as it actually is

**Files:** `infrastructure/cloud/azure/credentials.py` (51 lines),
`session.py` (84), `collector.py`, `errors.py`.

```
Expected                          Actual
--------                          ------
Tenant                            (no binding — same gap as AWS)
  ↓                                 ↓
Credential reference              AzureCredentialConfig(subscription_id, tenant_id?, resource_group?)
  ↓                                 ↓
Token acquisition                 DefaultAzureCredential — NEVER exercised until first API call
  ↓                                 ↓
Azure tenant VALIDATION           ✗ none
  ↓                                 ↓
Subscription VALIDATION           ✗ none — subscription_id is used, never verified
  ↓                                 ↓
Azure SDK clients                 5 management clients in an AzureClients bundle
  ↓                                 ↓
Collectors                        5 registered
  ↓                                 ↓
Scan                              ScanCloudAccount  ← no production caller at all
```

### 3.1 Credentials — same discipline as AWS

`AzureCredentialConfig` has no `client_secret`, no password, no
certificate field. Authentication goes through
`DefaultAzureCredential`, Azure's documented chain (environment,
workload/managed identity, Azure CLI, …). Same reasoning, same
strength: a secret never modelled cannot leak.

### 3.2 🔴 P0 — `tenant_id` does not do what it appears to do

```python
credential = (
    DefaultAzureCredential(interactive_browser_tenant_id=config.tenant_id)
    if config.tenant_id
    else DefaultAzureCredential()
)
```

`interactive_browser_tenant_id` scopes **only the interactive-browser
sub-credential** within the chain. In any realistic deployment — managed
identity, workload identity, environment-variable service principal —
the interactive browser credential is never the one that resolves.

So the configured Azure tenant is **silently ignored** for every
credential type that would actually be used in production. A config that
names tenant X can authenticate against tenant Y without complaint. The
field reads like a constraint and is not one.

The parameters that would actually constrain the chain are
`DefaultAzureCredential(managed_identity_client_id=…)` together with
`AZURE_TENANT_ID` in the environment, or an explicit
`ClientSecretCredential(tenant_id=…, …)`. Neither is used.

This is worse than the AWS gap in one respect: the AWS code makes no
claim to validate. This code *looks* like it constrains tenant and does
not, so a reviewer skimming it would reasonably conclude the check
exists.

### 3.3 🔴 P0 — no subscription validation, and no token preflight

`subscription_id` is passed straight into five management client
constructors and becomes `account_id` on every collected resource. It is
never verified to exist, to be accessible, or to belong to the
authenticated principal.

There is also no equivalent of AWS's `GetCallerIdentity` round trip. The
Azure collector's own comment says none is needed:

> *"The subscription id is the Azure account boundary and is always known
> from the client bundle — no equivalent of AWS's `sts:GetCallerIdentity`
> round trip is needed."*

**That reasoning is wrong, and the comment should not be trusted.** It
conflates *knowing what we intend to scan* with *knowing what we are
authenticated as*. The subscription id is known because we typed it into
a config; `GetCallerIdentity` answers a different question — *who is this
credential?* Azure's analogue would be decoding the token's `oid`/`tid`
claims, or calling `Microsoft.Resources/subscriptions/{id}` to confirm
the principal can see it.

The practical consequence: `DefaultAzureCredential` acquires no token
until the first API call, so a completely invalid credential produces no
error until deep inside the first collector, attributed to that
collector rather than to authentication.

### 3.4 Azure failure-case matrix

| # | Case | Classification | Evidence |
|---|---|---|---|
| 1 | Missing credentials | 🟡 PARTIALLY HANDLED | `ClientAuthenticationError` → `AzureAuthenticationError`, but only at first API call, mis-attributed to a collector |
| 2 | Invalid client secret | 🟡 PARTIALLY HANDLED | Same |
| 3 | Expired credentials | 🟡 PARTIALLY HANDLED | SDK refreshes its own tokens; untested here |
| 4 | Wrong tenant | 🔴 **NOT HANDLED** | §3.2 — the parameter does not constrain |
| 5 | Wrong subscription | 🔴 **NOT HANDLED** | §3.3 — never validated |
| 6 | Insufficient RBAC | ✅ HANDLED | 403 → `AzurePermissionError`; per-collector, scan continues |
| 7 | Graph permission denial | ➖ N/A | **No Microsoft Graph client exists.** No Entra ID collector, so no Graph permissions are requested |
| 8 | Throttling | 🟡 PARTIALLY HANDLED | 429 → `AzureServiceError`; `resilience.py` is **AWS-shaped** and not applied to the Azure path |
| 9 | Token acquisition failure | 🟡 PARTIALLY HANDLED | Surfaces late, as above |
| 10 | API/network failure | ✅ HANDLED | → `AzureServiceError` |

---

## 4. 🔴 P0 — there is no tenant ↔ cloud account binding

This is the finding that makes §2.3 unfixable in isolation.

```python
@dataclass
class Tenant:
    id: TenantId
    name: str
```

That is the entire tenant model. There is **no** store anywhere in the
repository recording that *ComplianceIQ tenant `acme` owns AWS account
`111111111111`*. Verified: no such field, no such table, no such
repository, no such config.

Answering the plan's §5 questions directly:

| Question | Answer |
|---|---|
| Where is tenant ownership of a cloud account stored? | **Nowhere.** |
| How is an AWS account id associated with a tenant? | Only *after the fact*, as a label on collected resources. |
| How is an Azure subscription associated? | Same. |
| Can one tenant have multiple cloud accounts? | Yes, incidentally — `account_id` is per-resource. Nothing declares the set. |
| Can one cloud account appear under another tenant? | **Yes.** Nothing prevents it. |
| Does the scanner validate the relationship before collecting? | **No.** There is no relationship to validate. |

The architecture is *deliberately* clear that the cloud account must
never determine ComplianceIQ tenancy — `ScanTarget`'s docstring says so
explicitly, and that principle is correct. But the inverse control is
also absent: the tenant never asserts which cloud accounts are legitimately
its own.

### 4.1 What is genuinely safe

Cross-tenant contamination **within the database** is well defended and
tested. Every repository query filters tenant-first; the STEP 4/5/6
suites prove tenant A cannot read tenant B's findings, attack paths, or
scans, using ids that differ only by prefix.

`domain/tenants/isolation.py` and `TenantIsolationViolation` guard the
domain layer, and `BuildResourceGraph` rejects resources whose
`tenant_id` does not match the graph's.

**So the risk is not cross-tenant leakage of stored data. It is
misattribution at collection time** — data that was never tenant A's
entering the system labelled as tenant A's, after which every downstream
control faithfully protects the wrong answer.

---

## 5. 🟡 Production wiring — the scan pipeline has no production caller

```
$ grep -rn "AwsSessionFactory|AzureSessionFactory" --include=*.py .
scripts/dev_scan_aws.py:44,65
```

The **only** caller of `AwsSessionFactory` outside tests is a developer
script. `AzureSessionFactory` has no caller at all outside tests.

`composition.py` wires `submit_scan`, `get_scan` and `list_scans` to
`_UnavailableScanSubmission`, which returns **503** with a clear reason.
Its docstring is explicit that this is a deliberate, visible gap rather
than an oversight, because a real scan needs a credential reference and
a rule catalog path that are deployment inputs.

That is the honest choice, and the 503 is better than a half-wired
pipeline failing confusingly. It has one consequence for this audit that
must be stated: **no cloud authentication code path is reachable from
the running API today.** Every AWS/Azure auth classification above
describes code that is correct-looking and unreached in production.

---

## 6. Secret handling — ✅ READY

| Question | Answer | Evidence |
|---|---|---|
| Are secrets ever logged? | No secret is ever *held*, so none can be logged. Log records carry correlation id, tenant, subject, method, path, status. | `presentation/middleware.py` |
| Credentials in findings? | No. `redact()` is applied to finding evidence, resource attributes, attack path evidence and edge evidence at the persistence boundary. | `mappers/redaction.py` |
| Credentials in PostgreSQL? | No. Same guard, plus a test inserting `AKIAIOSFODNN7EXAMPLE` and asserting it is redacted. | `test_persistence_security.py` |
| Credentials in error messages? | 🟡 **Partially.** Both translators build `f"{context}: {exc}"`, embedding raw SDK exception text. See below. |
| Credentials in graph nodes? | No. Nodes carry identity, provenance, confidence — no attribute payload. |
| Private keys or tokens in API responses? | No. JWKS exposes modulus and exponent only; a test asserts the exact key set and that no private RSA component (`d`,`p`,`q`,`dp`,`dq`,`qi`) appears. |

**Redaction design.** Key-name matching over 16 markers, with a
9-entry allowlist for names that *mention* a credential without carrying
one (`access_key_count`, `kms_key_id`, `key_manager`). It redacts rather
than raises, so one suspicious key does not discard 10,000 good
findings. Recurses into nested mappings and lists.

**The one gap: exception text.** `f"{context}: {exc}"` in both
`translate_client_error` and `translate_azure_error` embeds the SDK's
own message. AWS `ClientError` strings are generally safe; Azure SDK
errors can include request URLs, and a SAS-style URL carries its
credential in the query string. `ScanError.message` is documented as
"must already be sanitized by the caller" — the caller is these
translators, and they do not sanitize.

Whether this is exploitable depends on which Azure error shapes actually
occur, which is unknown because none has been observed live.
**Classification: 🟡 PARTIAL — needs live verification.** The API's own
500 handler is clean (a test asserts a Postgres URL with a password
never reaches the client), so the exposure is limited to `scan_errors`
rows and logs, not HTTP responses.

---

## 7. Test coverage — what actually exists

| Component | Code | Unit tests | Integration | Security tests | Live-verified |
|---|---|---|---|---|---|
| AWS credential config | YES | YES (3) | NO | PARTIAL — asserts no key fields | NO |
| AWS session factory | YES | YES (5, all `mock.patch`) | Opt-in, skipped | PARTIAL | **NO** |
| AWS STS account resolution | YES | PARTIAL — resolution only, never validation | NO | NO | **NO** |
| AWS role assumption | YES | YES (2) | NO | NO | **NO** |
| Azure credential config | YES | NO — no test file references it | NO | NO | NO |
| Azure session factory | YES | **NO** | Opt-in, skipped | NO | **NO** |
| Azure tenant/subscription validation | **NO CODE** | ➖ | ➖ | ➖ | ➖ |
| Tenant ↔ account binding | **NO CODE** | ➖ | ➖ | ➖ | ➖ |
| Secret redaction | YES | YES | YES (real Postgres) | YES | N/A |
| Error translation (AWS) | YES | YES | NO | NO | NO |
| Error translation (Azure) | YES | YES | NO | NO | NO |

`AzureSessionFactory` appears in **zero** unit tests. The 60 skipped
tests in every run are the opt-in AWS and Azure integration suites,
which require real credentials and have never executed.

---

## 8. Findings by priority

### P0

1. **No tenant ↔ cloud account binding exists** (§4). Misconfigured
   credentials silently attribute another account's entire estate to a
   tenant. Every downstream isolation control then protects the wrong
   data correctly.
2. **AWS account identity is discovered but never validated** (§2.3).
   `GetCallerIdentity` is called and its answer is used as a label, not
   as a gate.
3. **Azure `tenant_id` does not constrain authentication** (§3.2).
   `interactive_browser_tenant_id` scopes only the interactive-browser
   credential; the field reads as a control and is not one.
4. **Azure subscription is never validated** (§3.3), and the code
   comment asserting no identity round trip is needed is incorrect.

### P1

5. **No `ExternalId` on `AssumeRole`** (§2.2) — the standard
   confused-deputy defence for a SaaS scanner is not offered.
6. **Assumed-role sessions are never refreshed** (§2.4) — a scan longer
   than the session lifetime fails partway with a non-retryable error.
7. **`AzureSessionFactory` has no unit tests** (§7).
8. **Azure has no throttling/retry path** (§3.4 #8) — `resilience.py`
   is AWS-shaped and unapplied there.
9. **Raw SDK exception text is embedded in persisted errors** (§6).

### P2

10. `NoCredentialsError` is categorized as a service error, not an
    authentication error (§2.5 #1).
11. Region is validated as non-blank, never as a real region (§2.5 #10).
12. No permissions preflight — an operator learns what the role cannot
    read only from post-scan `ScanError` rows.

---

## 9. Live verification required

Not one line of cloud authentication in this repository has executed
against a real cloud account. Before any production claim:

- AWS: default chain, named profile, and cross-account `AssumeRole`
- AWS: behaviour of a scan exceeding the assumed-role session lifetime
- AWS: a genuinely partial-permission role, end to end
- Azure: `DefaultAzureCredential` under managed identity **and** under a
  service principal, confirming what §3.2 predicts
- Azure: a wrong-subscription and wrong-tenant configuration
- Azure: the actual text of `HttpResponseError` under 403/429, to settle
  §6's redaction question with evidence rather than inference

---

## 10. Classification summary

```
AWS cloud authentication:
  IMPLEMENTED + TESTED WITH FAKES
  🔴 NOT READY — account validation absent
  ⚠️ LIVE AWS VERIFICATION REQUIRED

Azure cloud authentication:
  IMPLEMENTED + PARTIALLY TESTED WITH FAKES
  🔴 NOT READY — tenant and subscription validation absent
  ⚠️ LIVE AZURE VERIFICATION REQUIRED

Credential/secret handling:
  ✅ READY — secrets are never modelled, and redaction backstops the boundary
  🟡 one gap: raw SDK exception text in persisted errors

Tenant ↔ cloud account binding:
  🔴 NOT READY — does not exist
```
