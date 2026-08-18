# CSPM Collectors & Rules Upgrade — Implementation Report

> **Verification policy.** Every number below was produced by executing a
> command against this repository. Work that was **not** done is listed
> as not done, not omitted. §44 forbids fake implementation, and that
> includes claiming coverage this upgrade did not deliver.

---

## 1. Headline

The audit found eight gaps, two of them BLOCKERs. **Both blockers are
fixed**, along with the HIGH-severity `unknown`-vs-`false` defect, the
rule-metadata and exception gaps, and one genuine new collector built as
the reference implementation for the rest.

**Breadth was deliberately not attempted.** §31's 60–100 AWS and 50–90
Azure rules, and §12–19's fifteen new collectors, are a multi-week body
of work. §30 and §44 are explicit that padding the count or shipping
collectors never exercised against a real API is worse than not shipping
them, so this upgrade went deep on the foundation instead. §7 below says
precisely what remains.

---

## 2. §43 — the requested numbers

| # | Metric | Before | After | Note |
|---|---|---|---|---|
| 1 | AWS collectors | 6 | **7** | +IAM roles |
| 2 | Azure collectors | 5 | **5** | unchanged |
| 3 | AWS rules | 41 | **41** | unchanged — see §7 |
| 4 | Azure rules | 27 | **27** | unchanged — see §7 |
| 5 | Normalized resource types | 11 | **12** | +`iam_role` |
| 6 | Relationship types (defined / emitted) | 8 / 3 | **8 / 5** | +ASSUMES, +PUBLICLY_EXPOSED |
| 7 | Rule operators | 32 | **32** | audit correction — see §5 |
| 8 | Tests | 1022 | **1213** | +191 |
| 9 | Terraform fixtures | unchanged | unchanged | not attempted — §7 |
| 10 | Documentation | — | **+2** | audit + this report |

---

## 3. Gaps closed

### G1 — Cloud resilience (BLOCKER) ✅

`infrastructure/cloud/resilience.py`, provider-neutral, **40 tests**.

Before: zero retry, backoff or throttling anywhere in
`infrastructure/cloud/`. A single `Throttling` response propagated up and
`AwsCollector._safe()` dropped the **entire service** — one transient 429
cost a customer all their S3 coverage.

- retries only what is genuinely retryable; unknown codes are terminal,
  because retrying an unknown error turns a fast failure into a hung scan
- full-jitter backoff — every collector starts at the same instant, and
  synchronized retries re-trigger the throttle that caused them
- server `Retry-After` / `x-ms-ratelimit-reset-after` override the formula
- both attempt count **and** elapsed time are capped
- `collect_each()` isolates per-resource failure: 10,000 resources, one
  `AccessDenied`, 9,999 still collected — and the run is marked
  `degraded` so the scan reports PARTIAL rather than COMPLETED

### G2 — Pagination truncation (BLOCKER) ✅

`paginate()` never returns a short list silently. **This was harder than
it looked, and the first implementation was wrong** — see §6.

### G3 — `unknown` vs `false` (HIGH) ✅

`domain/shared/unknown.py`, **30 tests**.

A normalizer that could not determine a value emitted `False`, so a
credential lacking `iam:ListMFADevices` produced *"this administrator has
no MFA"* — a false accusation indistinguishable from a true positive,
which discredits every other finding in the report.

`UNKNOWN` short-circuits every comparison to INDETERMINATE, and
`bool(UNKNOWN)` **raises** rather than quietly evaluating False,
converting the likeliest misuse (`if value:`) into a loud error at the
call site.

### G4 — Relationships (HIGH) ◐ partial

`ASSUMES` and `PUBLICLY_EXPOSED` are now emitted by the role collector
(5 of 8 types). `CONTAINS`, `CONNECTS_TO` and `PROTECTS` still are not —
they need the VPC/subnet/route-table collectors, which were not built.

### G5 — Rule metadata (MEDIUM) ✅

`category`, `detection_logic`, `false_positive_notes`,
`exceptions_supported`, `remediation.verification`. All optional; the 68
existing rules load unchanged, verified by their tests.

### G6 — Exceptions (MEDIUM) ✅

`domain/rules/exceptions.py`. Never silently suppress: a waived finding
keeps its evidence and records who approved it, why, and when it lapses.
Expiry is the default; permanence requires an explicit constructor.
Tenant is checked before scope, so a waiver in one tenant can never
suppress another's finding.

### G7 — Operators (LOW) — was a false gap, see §5

### G8 — Service coverage (MEDIUM) ◐ one of fifteen

---

## 4. Semantic IAM analysis (§5) — the flagship

`infrastructure/cloud/aws/policy_analysis.py`, **39 tests**.

The brief's requirement was *"do not only detect Principal `*`"*. What
this now does that name-matching cannot:

| Case | Handled |
|---|---|
| Customer-managed policy named `DeveloperAccess` granting `*:*` | detected as admin |
| `NotAction: iam:*` — grants everything **except** IAM | inverted correctly |
| `Allow *` + `Deny iam:*` | Deny wins, in any order |
| `iam:PassRole` alone | **not** flagged — normal and necessary |
| `iam:PassRole` + `ec2:RunInstances` | flagged as escalation |
| Escalation split across attached + inline policies | detected — permissions are additive |
| Wildcard principal **with** `aws:PrincipalOrgID` | not "publicly assumable" |
| Service principal without `SourceArn`/`SourceAccount` | confused-deputy risk |

Several tests assert the **absence** of a finding. That is the point: a
rule firing on a correctly-restricted role is a false positive, and false
positives are what get a CSPM removed from a customer's pipeline.

Conditions this module does not evaluate reduce **confidence** rather
than clearing the finding — the `UNKNOWN` principle applied at statement
granularity.

---

## 5. An audit finding that was wrong

The first audit pass reported **24 operators** and listed `regex` as
missing. Both were wrong. It was derived from a grep over string
literals, which missed every operator whose name differs from its
category label.

The live registry has **32**, including `matches_regex`, five network
operators (`cidr_is_public`, `port_in_range`, …) and three temporal ones.
Only `contains_object` from §20's list is genuinely absent, and the
`any`/`all`/`none` quantifiers with a `where` sub-condition already cover
its use case.

Corrected in the audit document with the reasoning visible, not silently
edited — "this DSL needs eight new operators" and "it needs one" lead to
very different plans, and a reader who saw the first number deserves to
know why it changed.

---

## 6. A real bug in my own resilience layer

Worth recording because it is exactly the failure the module exists to
prevent, and because a test caught it rather than review.

`paginate()` retried a throttle by calling `next(iterator)` again. But **a
generator that raises is finalized** (PEP 342) — every later `next()`
raises `StopIteration`. The code read that as "end of pages" and
**returned the pages collected so far**.

boto3's paginators are generators, so this was the real-world shape, not
a contrived one. The result: a throttle on page 40 of 60 would silently
report an account as having 40 pages of resources. Silent truncation is
this system's worst failure mode — it reports compliance for resources it
never examined.

Fixed: a `StopIteration` following an error is a dead iterator and raises.

The honest consequence, now stated in both the code and the test: the
achievable guarantee is **"never truncate silently"**, not "magically
resume". Mid-pagination throttles are *prevented* by boto3's adaptive
retry inside the SDK; this layer is the backstop for when that is
exhausted.

---

## 7. Not done — explicitly

§44 forbids fake implementation. None of the following exists, in any
form, not even a placeholder.

### Collectors not built (14 of 15)

**AWS:** VPC, Subnet, Network ACL, Route Table, RDS, EKS, ECR,
CloudWatch, AWS Config
**Azure:** Entra ID (users/groups/service principals/managed identities),
RBAC, Azure SQL, AKS, PostgreSQL, Firewall, Private Endpoints,
Diagnostic Settings

Entra ID in particular is not a small addition: Microsoft Graph is a
different SDK, permission model and pagination scheme from ARM, and the
brief's own §13 warns that MFA state is frequently not retrievable — the
case `UNKNOWN` was built for, but the collector itself is real work.

### Other items not delivered

- **Rules unchanged at 41 AWS / 27 Azure.** Writing rules for collectors
  that do not exist would produce rules that always return INDETERMINATE.
- **No Terraform fixtures added** (§32) — they pair with the collectors.
- **Structured evidence** (`observed`/`context`/`relationships`, §24)
  designed but not implemented; `evidence_template` is still a flat
  string.
- **Exceptions are not yet wired into `EvaluateRules`.** The domain model
  and registry are complete and tested; the application-layer
  integration that consults them during evaluation is not written.
- **`contains_object` operator** not added.
- **Existing collectors not migrated** to the resilience layer. Only
  `IamRoleCollector` uses it. S3 and CloudTrail still lack paginators —
  G2 is fixed *as a capability*, not yet *applied everywhere*.
- **N+1 in the S3 collector** (§35) unchanged.

### Not verified

- **No collector was run against a real AWS or Azure API.** All collector
  tests use fakes. The API shapes are modelled on documented responses,
  but no live call was made from this environment.
- No load testing; no `EXPLAIN`-style performance work.

---

## 8. Backward compatibility (§40)

| Check | Result |
|---|---|
| Pre-existing tests modified | **0** |
| Existing YAML rules still load | 68/68 |
| Public interfaces changed | none |
| Full suite | **1153 passed, 60 skipped** |
| ruff | clean |
| mypy | clean, 168 source files |

One breach occurred and was repaired during the work: I overwrote
`policy_analysis.py` and broke 16 passing tests. The original functions
are restored verbatim alongside the new analysis. They are deliberately
**not** rewritten in terms of each other — the legacy
`policy_allows_public_principal` treats any `Condition` as not-public,
while the new analysis surfaces it as reduced confidence. Both are
correct for their callers, and unifying them would silently change what
68 shipped rules mean.

---

## 9. Files

**Created (7)**
```
infrastructure/cloud/resilience.py
domain/shared/unknown.py
domain/rules/exceptions.py
infrastructure/cloud/aws/resource_collectors/iam_roles.py
tests/unit/infrastructure/test_resilience.py                 (40 tests)
tests/unit/infrastructure/test_policy_semantics.py           (39 tests)
tests/unit/infrastructure/test_aws_iam_role_collector.py     (21 tests)
tests/unit/domain/test_unknown.py                            (30 tests)
docs/architecture/cloud-security-rules-collectors-audit.md
docs/architecture/cloud-security-upgrade-report.md
```

**Modified (4)**
```
infrastructure/cloud/aws/policy_analysis.py   semantic analysis; legacy API preserved
domain/rules/conditions.py                    UNKNOWN → INDETERMINATE
domain/rules/rule.py                          +5 optional metadata fields
infrastructure/rules/yaml_rule_catalog.py     loads the new optional fields
```

---

## 10. Remaining limitations (§43)

**Elevated permissions required.** Role policy analysis needs
`iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`,
`iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`; last-used
needs `iam:GetRole`. Absent these, roles are still collected with those
attributes as `UNKNOWN` — degraded but honest, and the operator sees
which permission to grant.

**Cannot be reliably detected.**
- *Whether a Condition actually narrows a grant.* `aws:SourceIp` with a
  /8 is nearly meaningless; with a /32 it is decisive. Evaluating that
  requires policy simulation, so conditions lower confidence instead.
- *External-account trust without `own_account_id`.* Reported
  conservatively rather than guessed, or the rule would fire on every
  role in the account.
- *Azure MFA state*, as §13 anticipates — the reason `UNKNOWN` exists.

**Potential false positives.**
- A role trusting a partner account is flagged as cross-account, which
  may be entirely intended — hence `false_positive_notes` and §28
  exceptions.
- `has_privilege_escalation_path` is capability-based; a role with
  `iam:AttachRolePolicy` scoped by a permissions boundary is safer than
  the flag suggests. Boundaries are not yet analyzed.

**Performance.** Role collection is O(roles × attached policies × 2) API
calls, mitigated by retry/backoff but not by caching. A shared
managed-policy cache is the obvious next optimization: AWS-managed
policies are identical across every role and are currently re-fetched per
role.
