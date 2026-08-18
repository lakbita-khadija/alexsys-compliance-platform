# Phase 9 — Answers

**1. Depending on `BaseCollector` rather than `AwsCollector` — what does it enable?**

- **One pipeline, both clouds.** `AwsCollector` and `AzureCollector` are
  both adapters behind the same port. Adding GCP would need no change to
  `ScanCloudAccount`.
- **Testing without cloud credentials.** `StaticCollector` in the test
  suites returns a fixed list. Every pipeline test — including the attack
  path integration tests — runs in milliseconds with no network.

Also: it keeps the dependency arrow pointing inward.
`application/` never imports `infrastructure/`, which is what
`tests/api/test_architecture.py` enforces.

**2. The `scan_id` collision.**

Old form: `f"{tenant_id}:{provider}:{scanned_at}"` — no account
component. Two scans of two different AWS accounts in the same tenant at
the same instant produced a **byte-identical** `scan_id`.

Since `scan_id` was intended as a persistence key, one scan's results
would collide with the other's.

Fixed by deriving an account component from the collected resources:
one account → that account, several → `"mixed"`, none →
`"unknown-account"`. Read from the resources rather than taken as a
parameter, so no caller signature changed.

Note the honest limitation recorded in the docstring: `"unknown-account"`
is still not unique across two *unresolved* accounts. Phase 4 persistence
does not rely on this string — it derives its own scan key from the
`ScanTarget`.

**3. Remove `graph=graph` from `evaluate`.**

Every `relationship` condition **raises** `InvalidRuleCondition` —
deliberately, because a missing graph is a caller wiring bug, not a data
gap. The scan aborts loudly.

**Would unit tests catch it?** *Now* yes; **originally no.** That is the
history: the tests that exercised `ScanCloudAccount` used a **fake
catalog** containing no cross-resource rules, and the tests using the real
catalog bypassed `ScanCloudAccount` entirely. Neither combination hit the
path.

`tests/unit/application/test_scan_pipeline_regressions.py` was written
specifically to close it — it drives the real pipeline with the **real
68-rule catalog**.

**4. Remove `resources=resources` from `analyze`. Why more dangerous?**

Nothing raises. The analyzer builds an empty attributes map, and the two
attribute-driven scenarios (`internet_to_sensitive_data`,
`internet_to_exposed_workload`) find **nothing**. Scenario 4 also degrades,
since it needs exposure attributes on the target.

**Why more dangerous than the graph case:** the graph omission *fails
loudly* — a raise, a stack trace, an aborted scan, someone investigates.
The resources omission **fails silently and plausibly**: the scan
completes, results look normal, there are simply fewer attack paths. And
"fewer attack paths" is indistinguishable from "a healthier estate."

Loud failures get fixed. Quiet ones ship.

Hence `test_resources_reach_the_analyzer`, whose docstring names exactly
this: *"a smaller result, not an error, and therefore easy to miss."*

**5. Why abort on a foreign-tenant resource rather than filter it?**

Because it is a **security failure, not a data quality problem**.

A collector returning another tenant's resource means one of: credentials
are misconfigured and pointed at the wrong account; a caching bug is
leaking data across tenants; or the tenant id was mis-plumbed.

Every one of those is a **cross-tenant data leak in progress**. Filtering
would silently discard the evidence and let the underlying fault continue
— and the next bug might leak in a direction nothing checks.

`ensure_same_tenant` raises `TenantIsolationViolation`. In a multi-tenant
security product, failing closed on isolation is the only defensible
choice.

**6. Which stages degrade silently rather than raising?**

Two, and they are the two the codebase writes explicit warnings about:

- **Attack path analysis without `resources`** — fewer paths, no error.
- **Drift detection without `previous_snapshot`** — `drift_events = ()`,
  no error. Legitimate on a first scan, but indistinguishable from a
  caller that forgot.

Partially: **`ScanConfiguration.rule_ids`** filters the catalog, so a
wrong id list silently evaluates fewer rules.

Everything else fails loudly: validation raises, collection raises,
tenant/provider mismatch raises, missing graph raises.

The general design intent — *loud failure beats quiet wrong answers* — is
followed everywhere it can be. The two exceptions exist for backward
compatibility, and both are covered by tests that assert the wiring is
present.

**7. Where `UNKNOWN` enters and surfaces.**

```
Cloud API ──AccessDenied──▶ Collector
                              │  ← UNKNOWN ENTERS (attributes)
                              ▼
                        NormalizedResource
                              │
              ┌───────────────┴────────────────┐
              ▼                                ▼
        Rule Engine                    Attack Path Analysis
   is_unknown() → INDETERMINATE     _definitely_true() → False
              │                                │
              ▼                                ▼
   Finding.status = INDETERMINATE      no path fabricated
              │                       evidence_incomplete = True
              │                       incompleteness penalty −20
              │                                │
              └──────────────┬─────────────────┘
                             ▼
                         ScanResult
                             │  ← UNKNOWN SURFACES
                             ▼
          INDETERMINATE findings + reduced-confidence paths
```

**Enters** at exactly one place: a collector that could not read an
attribute.

**Surfaces** in three:
- `FindingStatus.INDETERMINATE` — "the scanner needs more permission"
- The attack path incompleteness penalty and `evidence_incomplete` flag
- `Finding.indeterminate_resources` — neighbours whose contribution
  could not be determined

The key property: it is **never converted** to `True` or `False` anywhere
in between. `UNKNOWN.__bool__` raises, so the conversion cannot happen by
accident, and `_definitely_true()` makes the safe reading explicit in the
attack path layer.
