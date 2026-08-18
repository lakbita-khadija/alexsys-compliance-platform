# Phase 1 — Answers

**1. `AccessDenied` → `public = False`. What is the harm?**

The bucket is reported **compliant**. If it is genuinely public, the
customer has an internet-readable data store and ComplianceIQ told them it
was fine. That is a false negative in the most damaging direction.

The subtler harm: the failure is *invisible*. There is no error, no
warning, no degraded-confidence marker. The scan looks completely healthy.
And because the same missing permission affects every bucket, the whole
estate is silently mis-scored.

The real fix is not "handle the error" but "represent the third state" —
which is what `UNKNOWN` is for.

**2. Why does `UNKNOWN.__bool__` raise?**

Because the dangerous mistake is one you write *by reflex*:

```python
if resource.attributes["public"]:
```

If `UNKNOWN` were falsy, that line would silently treat "we could not
check" as "not public", and it would look like perfectly ordinary Python.
Raising turns a silent wrong answer into a loud stack trace at the exact
line that made the wrong assumption.

It is defensive design aimed at the *author*, not the runtime.

**3. Why can't `paginate()` just retry `next()`?**

Because of PEP 342 generator semantics: **a generator that raises is
finalized**. Once the paginator's generator has propagated an exception it
is dead. Calling `next()` on it again does not resume — it raises
`StopIteration`, which is indistinguishable from "you have reached the
last page."

So the naive retry loop reads a fatal error as normal completion and
returns whatever it had accumulated. The fix tracks whether an error was
seen and raises `RetryBudgetExhausted` instead of returning a partial
list.

**4. Why set all five privilege attributes to `UNKNOWN`?**

Because they are all derived from the **same** enumeration. If
`ListAttachedRolePolicies` was denied, we did not read the policies at
all — so we know nothing about administrator access, wildcards, escalation
paths or `PassRole`. Marking only one would imply the other four were
determined, which is a lie.

Doing it uniformly also gives rules a **predictable degraded shape**: the
constant `_POLICY_ATTRIBUTES` in `iam_roles.py` names the set once, so
every rule sees the same thing under the same failure.

**5. `Principal: "*"` with an org-ID condition — publicly assumable?**

**No.** The condition constrains the wildcard to principals in that AWS
organization. Reporting it as publicly assumable would be a false
positive on a very common, intentional pattern.

This is exactly why `policy_analysis.py` does *semantic* analysis rather
than string matching for `"*"`. It tracks `constraining_conditions` and
`conditioned_statement_count`, and only reports `is_publicly_assumable`
for an **unconditional** wildcard principal.

Test coverage: `tests/unit/infrastructure/test_policy_semantics.py`.

**6. Adding an RDS collector — touch and don't touch.**

Touch (**none of these files exist — this is the prospective shape**):
- `infrastructure/cloud/aws/resource_collectors/rds.py`
- `infrastructure/cloud/aws/normalizers/rds.py`
- `infrastructure/cloud/aws/collector.py` (register it)
- `rules/aws/rds.yaml` (optional)
- `tests/unit/infrastructure/test_aws_rds_collector.py`
- optionally `domain/attack_paths/classification.py` — one row in
  `_ROLE_BY_RESOURCE_TYPE` if RDS should be an attack path target

Must **not** touch: `domain/rules/`, `domain/graph/models.py`,
`application/scanning/scan_cloud_account.py`. If a new collector forces a
change there, the abstraction has failed.

**7. Crash vs truncation — which is worse?**

**Truncation, clearly.**

A crash is loud, attributable and fails closed. Someone gets paged, the
scan is retried, no wrong answer reaches a customer.

Truncation fails *open* and silently. The report looks complete, the
customer believes their estate was assessed, and the resources that were
never examined are indistinguishable from resources that passed. They then
make security decisions on it.

The general principle in this codebase: **loud failure beats quiet wrong
answers**, which is why `paginate()` raises rather than returning what it
has.

**8. `has_administrator_access` is `UNKNOWN` — what must a rule return?**

`INDETERMINATE`.

Not `False`, because "we could not read the policy" is not evidence the
role lacks admin access — the role may well have it. Returning `False`
converts a *scanner permission problem* into a *compliance pass*, hiding a
potentially critical finding.

Not `True` either — that manufactures a finding out of a gap and, applied
across an estate, produces mass false positives.

Mechanically: `domain/rules/conditions.py` checks `is_unknown(value)`
after the presence check and returns `_INDETERMINATE`. The Kleene
combinators then propagate it — an `AND` containing INDETERMINATE cannot
be MATCHED unless something else is definitively `False`.
