# Phase 4 — Answers

**1. `AND` with INDETERMINATE — the asymmetry.**

- `{"and": [MATCHED, INDETERMINATE]}` → **INDETERMINATE**
- `{"and": [NOT_MATCHED, INDETERMINATE]}` → **NOT_MATCHED**

The asymmetry is sound, not a quirk. `AND` is false if *any* operand is
definitely false — you do not need to resolve the unknown to know the
answer. But if everything you *can* evaluate is true and one operand is
unknown, the conjunction genuinely depends on the unknown, so you must
report that you cannot tell.

Security reading: "the instance is public AND its SG is unrestricted, but
we could not read the SG" → don't know. "The instance is NOT public and we
could not read the SG" → not a finding regardless of the SG.

**2. `_kleene_or` raises on empty, `_existence_quantified_or` doesn't.**

They mean different things.

An empty `or` in a rule's own condition tree is a **rule-authoring bug** —
someone wrote `{"or": []}`, which asserts nothing. Raising surfaces it at
catalog load rather than letting a broken rule sit in the catalog silently
never firing.

Zero neighbours in a relationship condition is a **determinate fact about
the infrastructure**: this instance is attached to no security group.
"At least one neighbour satisfies X" over zero neighbours is vacuously
false → `NOT_MATCHED`.

Same truth table, deliberately different names and different empty-cases,
so the distinction cannot be lost by accident.

**3. `age_gt_days` with no `as_of`.**

It **raises `InvalidRuleCondition`**.

Not `datetime.now()`, because that would destroy determinism: the same
rule against the same collected resource would produce different results
depending on when it ran. You could not diff two scans, you could not
reproduce a finding, and a test suite could not pin behaviour.

The same discipline applies across the domain — `DiffEngine` takes an
explicit timestamp too. Time is an **input**, never an ambient read.

**4. `is_null` vs `not_exists` — the KMS example.**

A KMS key's rotation status:

- **Key absent** (`not_exists`) — the resource type has no such concept,
  e.g. an asymmetric key where rotation does not apply. The rule should
  not fire.
- **Key present with value `None`** (`is_null`) — AWS returned the field
  and it is null. That is a *collected fact*, and it may well be a
  finding.

Collapsing them would either flood the report with findings on keys where
rotation is meaningless, or hide genuine nulls. `rules/aws/kms.yaml`
carries the precedent.

Third distinct state: `UNKNOWN` — we tried to read it and were denied.
Three genuinely different situations, three different representations.

**5. Neighbour in the graph, missing from `resources_by_id`.**

**`INDETERMINATE`** for that neighbour, which then flows through
`_existence_quantified_or`.

Not skipped, because skipping would treat "we cannot evaluate this
neighbour" as "this neighbour does not satisfy the condition" — silently
converting a data gap into a compliant answer. If the only attached
security group is unreadable, the honest answer is "we don't know whether
this instance is exposed", not "it isn't".

Note the `MATCHED` short-circuit still applies: if *another* neighbour
definitively matches, the result is MATCHED regardless of the unreadable
one. An unknown cannot un-prove something already proven.

**6. Azure SQL with no private endpoint — YAML, and why it must not ship.**

```yaml
condition:
  and:
    - field: public_network_access
      operator: is_true
    - no_relationship: connects_to
      direction: outgoing
      target_type: private_endpoint
      requires_collected: private_endpoint
```

**Why it must not ship today:** there is no Azure SQL collector and no
private-endpoint collector. The graph would contain zero nodes of type
`private_endpoint`, so `requires_collected` would fail and the rule would
return **`INDETERMINATE` on every resource, forever**.

That is fake coverage — a rule in the catalog that can never produce a
verdict, inflating the rule count while detecting nothing. The guard is
working exactly as designed: it is refusing to let an absence rule run
without evidence that the relevant collector ran.

**7. `not(is_true(UNKNOWN))`.**

**`INDETERMINATE`.**

The inner leaf hits `is_unknown(value)` → `INDETERMINATE`, and Kleene
`NOT` maps `INDETERMINATE` to itself. "I don't know" negated is still "I
don't know".

This is the property that makes `UNKNOWN` safe to compose. If `NOT`
collapsed it to a boolean, a rule author could launder an unknown into a
confident answer just by inverting the condition — and the negated form is
often the natural way to write a compliance check ("NOT encrypted").

**8. Why does an invalid regex raise?**

Because it is a **rule-authoring bug**, not a data gap.

`INDETERMINATE` means "the data needed to decide was not collected" — an
operational signal that the scanner needs more access. A malformed regex
says nothing about the data; it says the rule is broken. Reporting it as
INDETERMINATE would file it in the operator's "check scanner permissions"
queue, where nobody would ever find it, and the rule would silently never
fire.

Same principle as `relationship` without a graph: **wiring and authoring
bugs must be loud; data gaps must be INDETERMINATE.**

**9. "Attached to exactly two security groups" — can the DSL express it?**

**No.** The `relationship` node is existence-quantified (OR across
neighbours) — it answers "does at least one neighbour satisfy X". It has
no notion of counting, and `no_relationship` only adds the zero case.

To add it you would need a **cardinality-quantified node**, e.g.:

```yaml
- relationship_count: attached_to
  direction: outgoing
  target_type: security_group
  operator: equals
  value: 2
```

Design constraints it would have to respect, learned from
`no_relationship`:

- A **new node type**, never a flag on `relationship` — seven shipped
  rules depend on the existing truth table.
- A **coverage guard**, because a count is an absence claim in disguise:
  if the SG collector was denied, every instance counts zero.
- Unreadable neighbours must make the count `INDETERMINATE`, not shrink
  it.
