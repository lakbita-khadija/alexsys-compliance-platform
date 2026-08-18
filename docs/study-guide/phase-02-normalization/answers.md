# Phase 2 — Answers

**1. Why does `resource_type` appear in three subsystems?**

1. **Rule scoping** — `Rule.applies_to_resource_type` decides whether a
   rule even runs against a resource.
2. **Graph queries** — `find_resources(graph, "s3_bucket")` and the
   `_by_type` index; also `target_type` filtering in relationship
   conditions.
3. **Attack path classification** — `_ROLE_BY_RESOURCE_TYPE` in
   `domain/attack_paths/classification.py` maps it to a `ResourceRole`.

Practical consequence: a typo in `resource_type` fails **silently** in all
three. The rule never fires, the query returns nothing, the node
classifies as `OTHER`. Nothing raises. This is a genuine fragility worth
knowing about.

**2. S3's missing `PUBLICLY_EXPOSED` edge — consequence and workaround?**

Consequence: **no graph traversal can discover a public bucket.** There is
no path from an internet node to it, because no edge connects them. A
query like `find_resources_exposed_to_internet()` will not return it.

Workaround in the analyzer: the `internet_to_sensitive_data` scenario
(`_exposed_sensitive_data` in `analyze_attack_paths.py`) reads the
bucket's **own attributes** — `public`,
`bucket_policy_allows_public_access` — via `public_exposure_evidence()`,
rather than looking for an edge. The resulting `AttackPath` has one node
and zero edges.

That is why the scoring model has two separate exposure contributions:
`EXPOSURE_DIRECT_INTERNET_EDGE` (+40) and
`EXPOSURE_ATTRIBUTE_EVIDENCE` (+35). Attribute evidence scores slightly
lower because it is one collector's reading rather than a modelled
relationship.

**3. Why is "port 22 is sensitive" a rule concern?**

Because it is a **policy judgement**, not an observation. A bastion host
deliberately exposing 22 to a corporate CIDR is fine; the same port open
to `0.0.0.0/0` on a database host is not. Different customers, frameworks
and environments answer it differently.

If you moved it into the normalizer:
- Changing the sensitive-port list would require a **collector release**,
  not a catalog update.
- The raw fact would be **lost** — you would store `is_risky: true` and
  could never re-evaluate under a different policy.
- Two rules needing different port sets could not coexist.

The normalizer reports `unrestricted_ingress_ports: (22, 3389)`; rules
decide.

**4. `network_default_action` on two Azure types — what defect?**

A Key Vault rule fired against **storage accounts**, because attribute
names are not globally unique and rules originally ran against every
resource. The rule read a field that existed on both types and produced
findings on the wrong resources.

Fixed by `Rule.applies_to_resource_type`. Critically, a rule that does not
apply produces **no finding at all**, not `INDETERMINATE` — the docstring
explains why: "this rule has nothing to say about this resource type" is a
different statement from "the data needed to decide was not collected",
and conflating them would bury every real INDETERMINATE under thousands of
irrelevant ones.

It was found by the conformance framework's `UNEXPECTED_FINDING`
classification, not by inspection.

**5. Why isn't `instance_profile_arn` enough for the attack path?**

Two reasons, and the second is the blocker:

- **It is an attribute, not an edge.** Graph traversal walks edges. No
  edge, no path.
- **An instance profile is not a role.** The ARN is
  `arn:aws:iam::…:instance-profile/MyProfile`, while the role is
  `arn:aws:iam::…:role/MyRole`. They are different resources. The profile
  *contains* a role, and discovering which one requires
  `iam:GetInstanceProfile` — a call no collector makes.

Names often match by convention, but a convention is not a fact.
Inferring the role from the profile name would be **fabricating the
relationship**, which §17 of the implementation brief forbids and which
`test_no_workload_to_identity_path_is_invented` explicitly asserts against.

This is why closing it is listed as **P1** in `next-work.md`: it is one
API call, and it unlocks the highest-value attack path in cloud security.

**6. When is omitting a key better than `UNKNOWN`?**

When the attribute **does not apply to that resource type at all**.

Example from the codebase: `root_volume_encrypted` is `None`/omitted when
an EC2 instance is instance-store-backed. There is no EBS root volume, so
encryption is not a property that can be true, false, or unknown — the
question is malformed.

`UNKNOWN` means *"this attribute applies and we could not determine it"* —
an operational signal that the scanner needs more permission. An absent
key means *"this attribute does not apply"* — nothing is wrong.

Rules distinguish them: `exists` / `not_exists` handle absence, while
every other operator returns `INDETERMINATE` for `UNKNOWN`. Conflating the
two would flood the operator with permission warnings for attributes that
were never relevant.
