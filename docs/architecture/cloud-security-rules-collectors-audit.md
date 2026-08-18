# Cloud Security Rules & Collectors — Audit

> **Status: audit only. No code was modified to produce this document.**
> Every count and claim below was obtained by reading or executing
> against this repository.

---

## 0. Executive summary

The existing architecture is sound and should be **evolved, not
replaced**. The rule engine already has three-valued Kleene logic,
provider-neutral normalization, and a working relationship node in the
DSL — those are the hard parts, and they are correct.

What is missing is almost entirely **operational hardening and breadth**,
not architecture. Ranked by how much damage each would do in a real
enterprise deployment:

| # | Gap | Severity | Why it matters |
|---|---|---|---|
| G1 | **No retry, backoff or throttling anywhere in `infrastructure/cloud/`** | **BLOCKER** | A scan of a real account *will* hit `Throttling`/`RequestLimitExceeded`. Today that aborts a whole service's collection. |
| G2 | **Incomplete pagination** — S3 and CloudTrail collectors use no paginator | **BLOCKER** | Silently truncates results past the first page. A CSPM that misses resources reports false compliance. |
| G3 | **No `unknown` tri-state at collection time** | **HIGH** | Normalizers emit `bool`. Nothing distinguishes "MFA disabled" from "MFA state not retrievable". §34 calls this critical, and it is the difference between a true finding and a defamatory one. |
| G4 | Relationship graph barely populated — 3 of 8 types, 5 emission sites | **HIGH** | Contextual rules (§21/§22) are impossible without edges. |
| G5 | Rule metadata missing `false_positive_notes`, `detection_logic`, `exceptions_supported`; remediation missing `verification` | **MEDIUM** | §27/§29. Drives false-positive triage. |
| G6 | No exception/suppression model (§28) | **MEDIUM** | Every enterprise needs accepted-risk handling. |
| G7 | Operator vocabulary missing `contains_object` | **LOW** | §20. See the correction below — the DSL is far richer than a first pass suggested. |
| G8 | Service coverage: AWS 6/14, Azure 5/13 | **MEDIUM** | Breadth, not correctness. |

**Nothing here requires breaking a public interface.** Every gap can be
closed additively.

---

## 1. Current architecture

```
boto3 / azure-sdk
      │
      ▼
resource_collectors/<service>.py     per-service, raise typed errors
      │
      ▼
normalizers/<service>.py             dict → NormalizedResource
      │
      ▼
AwsCollector / AzureCollector        _safe() per-service isolation
      │
      ▼
NormalizedResource ──▶ BuildResourceGraph ──▶ ResourceGraph
      │                                              │
      └──────────────▶ EvaluateRules ◀───────────────┘
                             │
                             ▼
                          Finding
```

The layering is correct and is AST-enforced. The per-service split is
the right granularity. `AwsCollector` already isolates per-service
failure (`_safe()` pattern, `AwsCollectionError` only when *all* services
fail) — that part of §3 is already satisfied.

---

## 2. Existing coverage — measured

### AWS — 6 services, 41 rules

| Service | Collector | Normalizer | Rules | Paginated |
|---|---|---|---|---|
| S3 | yes | yes | 8 | **no** |
| IAM (users) | yes | yes | 10 | yes (3) |
| EC2 | yes | yes | 5 | yes (1) |
| Security Groups | yes | yes | 8 | yes (1) |
| CloudTrail | yes | yes | 6 | **no** |
| KMS | yes | yes | 4 | yes (1) |

### Azure — 5 services, 27 rules

| Service | Collector | Normalizer | Rules |
|---|---|---|---|
| Storage | yes | yes | 7 |
| Network (NSG) | yes | yes | 7 |
| Compute (VM) | yes | yes | 3 |
| Key Vault | yes | yes | 5 |
| Monitor (Activity Log) | yes | yes | 5 |

**68 rules total.** Metadata is already rich: every rule carries `id`,
`version`, `title`, `description`, `rationale`, `service`, `domain`,
`severity`, `confidence`, `applies_to_resource_type`, `framework`,
`control_id`, `framework_mappings` (with a `status` field), `references`,
`tags`, `evidence_template`, and a three-key `remediation` block.

### Rule engine

- **32 operators**, enumerated from the live registry
  (`domain.rules.conditions._ALL_OPERATORS`) rather than by reading the
  source:

  | Category | Operators |
  |---|---|
  | Scalar | `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with` |
  | Boolean/null | `is_true`, `is_false`, `exists`, `not_exists`, `is_null`, `is_not_null` |
  | Numeric | `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal` |
  | Collection | `in`, `not_in`, `contains_any`, `contains_all`, `any`, `all`, `none` |
  | String | `matches_regex` |
  | Network | `cidr_contains`, `cidr_is_public`, `cidr_is_private`, `port_equals`, `port_in_range` |
  | Temporal | `age_gt_days`, `age_gte_days`, `age_lt_days` |

  > **Correction.** An earlier pass of this audit reported 24 operators
  > and listed `regex` as missing. That was wrong on both counts: it was
  > derived from a grep over string literals, which missed every operator
  > whose name differs from its category label. `matches_regex` exists,
  > as do five network operators and three temporal ones. Only
  > `contains_object` from §20's list is genuinely absent, and its use
  > case is largely served by the `any`/`all`/`none` quantifiers with a
  > `where` sub-condition.
  >
  > Recorded rather than quietly edited, because the difference between
  > "this DSL needs eight new operators" and "it needs one" changes the
  > plan, and a reader who saw the first number deserves to know why it
  > changed.
- **Three-valued Kleene logic**: MATCHED / NOT_MATCHED / INDETERMINATE,
  with proper `and`/`or`/`not` combinators. This is the single best thing
  in the codebase and §34's requirement is already satisfied *inside* the
  engine.
- **Relationship node** exists in the DSL and raises rather than
  returning INDETERMINATE when called without a graph — a deliberate,
  correct "wiring bug, not data gap" distinction.
- **`applies_to_resource_type`** gates rules per resource type, added
  after a real defect where an Azure Key Vault rule fired against storage
  accounts.

---

## 3. Gap detail

### G1 — No resilience layer (BLOCKER)

```
$ grep -rln "retry\|backoff\|Throttl\|RequestLimitExceeded\|TooManyRequests" infrastructure/cloud/
  (no matches)
```

There is no retry, no exponential backoff, no jitter, and no throttling
handling anywhere in the cloud layer. boto3's default `max_attempts=3`
"legacy" mode applies to some calls by accident, but it is not
configured, not adaptive, and Azure SDK calls have nothing equivalent.

**Consequence:** scanning an account with a few thousand resources will
hit `Throttling` or `RequestLimitExceeded`. Today that propagates as an
`AwsError`, and `_safe()` drops the **entire service** from the scan.
The scan is then reported PARTIAL — which is at least honest — but the
customer loses all S3 (or all IAM) coverage because of one transient
429.

This is the highest-value fix in the whole audit and everything else
depends on it, because adding more collectors multiplies the API call
volume that triggers it.

### G2 — Incomplete pagination (BLOCKER)

`s3.py` and `cloudtrail.py` use no paginator. `list_buckets` is genuinely
unpaginated in the S3 API, so S3 is fine — but `describe_trails` and the
per-bucket sub-calls need checking, and any new collector must not repeat
the omission.

**Silent truncation is the worst failure mode a CSPM has**: it reports
compliance for resources it never looked at.

### G3 — `unknown` is not representable at collection time (HIGH)

The rule engine handles INDETERMINATE correctly. The **collectors** do
not produce it. A normalizer that cannot determine a value emits `False`
or omits the key entirely:

- omitted key → the engine's `exists` returns NOT_MATCHED and most
  operators return INDETERMINATE, which is *accidentally* correct
- explicit `False` → the engine says "definitely non-compliant", which
  is **wrong** and produces a false positive

There is no way today for a normalizer to say "I looked, and I could not
determine this." §34 identifies this as critical, and it is the
difference between "this user has no MFA" (actionable) and "we lack
permission to read MFA state" (a scan configuration problem).

### G4 — Relationship graph barely populated (HIGH)

```
2 × ATTACHED_TO,  2 × ACCESSES,  1 × ALLOWS      (5 emission sites)
```

Five of eight relationship types are never emitted: `CONTAINS`,
`CONNECTS_TO`, `PROTECTS`, `ASSUMES`, `PUBLICLY_EXPOSED`.

The contextual rules §21 asks for — "EC2 has public IP **and** subnet
has internet route **and** SG allows 0.0.0.0/0" — cannot be written,
because the edges do not exist.

### G5–G7 — Metadata, exceptions, operators (MEDIUM)

- Missing rule fields: `category`, `detection_logic`,
  `false_positive_notes`, `exceptions_supported`
- `remediation` has `summary`/`why_it_matters`/`how_to_fix` but no
  `verification`
- No exception/suppression model at all
- Missing operators: `regex`, `contains_object`

`framework_mappings` already carries a `status` field, so §26's
`needs_validation` requirement needs only a documented vocabulary, not a
schema change.

---

## 4. Technical debt and fragile assumptions

| Issue | Where | Risk |
|---|---|---|
| No adaptive retry config on the boto3 session | `aws/session.py` | G1 |
| Per-bucket S3 sub-calls are N+1 (one `get_bucket_*` per bucket per property) | `s3.py` | §35 — a 5,000-bucket account makes ~35,000 calls |
| Normalizers return `False` for absent data | all normalizers | G3, false positives |
| No collection statistics (counts, durations, skipped) | collectors | §3 asks for them; also needed to prove coverage |
| `evidence_template` is a flat string | rule schema | §24 wants structured `observed`/`context`/`relationships` |
| Azure SDK exceptions not classified into retryable vs terminal | `azure/errors.py` | G1 |

---

## 5. Architectural risks

1. **Adding collectors before fixing G1 makes reliability worse.** Every
   new service multiplies call volume against an unprotected client.
   Resilience must come first.
2. **Adding rules before G3 multiplies false positives.** More rules over
   `False`-means-unknown data means more wrong findings, and false
   positives are what get a CSPM removed from a customer's pipeline.
3. **Contextual rules (§21) are blocked on G4.** Writing them before the
   edges exist would mean rules that always return INDETERMINATE.

This ordering is not negotiable and it drives the plan below.

---

## 6. Target architecture

```
                 ┌──────────────────────────────┐
                 │  resilience layer (NEW)      │
                 │  retry · backoff · jitter    │
                 │  throttle classification     │
                 │  page-through helper         │
                 │  per-call error isolation    │
                 └──────────────┬───────────────┘
                                │  wraps every SDK call
      ┌─────────────────────────┴─────────────────────────┐
      ▼                                                   ▼
 AWS collectors                                     Azure collectors
      │                                                   │
      ▼                                                   ▼
 normalizers ──▶ NormalizedResource (+ Unknown tri-state) ◀── normalizers
                                │
                                ▼
                 relationship resolution (EXPANDED)
                                │
                                ▼
                 ResourceGraph ──▶ rule engine (+regex, +contains_object)
                                │
                                ▼
                 Finding (+structured evidence, +exceptions)
```

---

## 7. Implementation plan

Ordered by dependency, not by prompt section.

| Phase | Work | Unblocks |
|---|---|---|
| **B1** | Resilience layer: retry/backoff/jitter, throttle classification, paginate helper, per-call isolation, collection stats | everything |
| **B2** | `Unknown` tri-state value + normalizer support + engine integration | correct findings |
| **C** | Rule metadata: `category`, `detection_logic`, `false_positive_notes`, `exceptions_supported`, `remediation.verification` | §27/§29 |
| **D** | Operators: `regex`, `contains_object` | policy-document rules |
| **E** | Exception/suppression model | §28 |
| **F** | Relationship expansion + contextual rules | §21/§22 |
| **G** | New AWS collectors (IAM roles, VPC/subnet/route/NACL, RDS, EKS, ECR, CloudWatch, Config) | breadth |
| **H** | New Azure collectors (Entra ID, RBAC, SQL, AKS, PostgreSQL, Firewall, Private Endpoint, Diagnostics) | breadth |
| **I** | Rule library expansion | breadth |
| **J** | Terraform fixtures | §32 |
| **K** | Tests + docs | §33/§39 |

### Realistic scope statement

§31 targets 60–100 AWS and 50–90 Azure rules, and §12–19 name **15 new
collectors** across two clouds — including Microsoft Graph integration
for Entra ID, which is a distinct SDK, a distinct permission model and a
distinct pagination scheme from ARM.

That is a multi-week body of work for a team. §30 and §44 are explicit
that padding the count or writing collectors that were never exercised
against a real API is worse than not writing them.

So the honest plan is: **implement B1 through F completely and
properly** — the foundation that every remaining item depends on and that
fixes the two BLOCKERs — then add collectors and rules in genuine
vertical slices, and report precisely what was and was not done rather
than claiming §45 in full.

Phases G–I will be delivered incrementally; anything not reached is
listed as remaining work in the final report, with no placeholder code
left behind.
