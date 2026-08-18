# Phase 6 — Answers

**1. Two scans, unchanged infrastructure — which field is identical?**

- **Identical:** `logical_finding_id` = `tenant:account:resource:rule`.
  None of those components varies with the scan.
- **Different:** `id` (the physical identity), which appends `scan_id`.

You need both because they answer different questions. The logical id
answers *"is this the same issue?"* — required for first-seen/last-seen,
resolution detection and regression detection. The physical id answers
*"which scan observed it?"* — required to keep an append-only history and
to attribute a finding to a point in time.

With only the logical id you would overwrite history. With only the
physical id every scan would look like a brand-new set of problems.

**2. Two unresolvable accounts — what went wrong, and does the sentinel fix it?**

Under the old code, `f"{resource.account_id!s}"` rendered `None` as the
**string `"None"`**. Two different accounts both produced
`acme:None:bucket-1:rule-1` — the same logical id. Their security history
merged onto one lifecycle row: a finding resolved in account A would look
resolved in account B.

**Does the sentinel fix it? Partially, and the docstring is explicit about
this.** `"unknown-account"` is still not unique across two unresolved
accounts. What it fixes is *honesty*: the value no longer masquerades as a
real account identifier, so anyone reading it knows the account was not
determined.

The real fix is at the persistence layer: Phase 4 stores identity
**components** as separate columns and keys the lifecycle on those, so it
never depends on parsing the composite string — which is unparseable
anyway, since `:` also appears inside ARNs.

**3. `sg-open` matched, `sg-closed` didn't — what's in `related_resources`?**

Only **`("sg-open",)`**.

`sg-closed` was traversed and examined, and it is *not* related to the
finding — it is a compliant resource. Naming it would send a responder to
investigate something that is fine. Over an estate, that noise is what
teaches people to ignore the "related resources" field entirely.

`RelationshipTrace.matched_resource_ids` filters on `satisfied is True`
for exactly this reason.

**4. `no_relationship` finds a satisfying private endpoint — include it?**

**No**, and this is the subtlest of the four decisions.

Under `no_relationship`, the semantics invert. A neighbour that satisfies
the `where` clause is evidence the control was **met** — the database
*does* have a private endpoint, so the absence rule correctly does not
fire.

If that endpoint appeared in `related_resources` on some other finding, it
would name a resource as implicated in a violation it in fact
**prevented**. Hence `RelationshipObservation.from_absence_check`, and the
filter `not o.from_absence_check` in `matched_resource_ids`.

**5. Why is `graph_context` attached only when the rule traversed?**

Because attaching a neighbourhood blob to every single-resource finding
would bloat every row for **no signal**. The overwhelming majority of the
68 rules are single-resource; they are related to nothing, and `None` is
the truthful value.

`RelationshipTrace.traversed` distinguishes "this rule is cross-resource
and found nothing" from "this rule never looked" — a distinction that
`related_resources == ()` alone cannot make.

**6. `NOT NULL DEFAULT '[]'` — why not nullable, and why keep the default?**

**Why not nullable:** the domain invariant is that `related_resources` is
a tuple of strings, sorted and deduplicated. `NULL` would mean "unknown",
but there is no unknown state here — a finding either named resources or
named none. Empty is the truthful value, and `NULL` would force every
reader to handle a state that cannot occur. (The mapper still does
`tuple(row.related_resources or [])` defensively.)

**Why the default is needed at all:** you cannot add a `NOT NULL` column
to a populated table without one. Every existing finding backfills to
"related to nothing" — truthful, since none of them recorded traversal.

**Why keep it after backfill:** during a rolling deploy, an older process
still running the previous release inserts rows that never mention these
columns. Without a server default, those inserts fail.

**7. Why is `relationship_path` deliberately absent?**

Because **nothing would write it.** `find_paths` exists and is tested, but
no rule produces a path — the DSL has no way to call it.

Adding the column would be decoration: a field that is always empty,
carried through the model, the mapper, a migration and the API, implying a
capability that does not exist. It is recorded as a limitation instead.

`related_resources` makes a weaker, honest claim: these are the neighbours
a rule matched. It does **not** claim they form a chain.

**8. `status=INDETERMINATE` — what should the operator do?**

**Grant the scanner more permission.** It is a *scanner* problem, not a
customer compliance problem — the finding is saying "ComplianceIQ could
not determine this", most often because an API call returned
`AccessDenied`.

The correct response is to check the scanning role's policy against the
required permissions, not to open a remediation ticket against the
resource.

The reason this is a first-class status rather than a log line: at scale,
a systematic INDETERMINATE across one resource type is the signal that a
whole category of checks is silently not running. If it were collapsed to
`PASS`, the estate would look clean while being entirely unassessed — the
exact failure `UNKNOWN` exists to prevent.
