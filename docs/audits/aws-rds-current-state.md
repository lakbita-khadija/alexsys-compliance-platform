# AWS RDS — Current State Audit

> **STEP 8B, audit phase. No code was modified.**
>
> Baseline before any change: **1796 passed, 60 skipped, 0 failed**;
> `ruff` clean; `mypy` clean over 191 source files.

---

## 1. Coverage

| Resource | Collector | Normalizer | Relation support | Rules | Terraform | Tests |
|---|---|---|---|---|---|---|
| **DB instance** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **DB cluster (Aurora)** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **DB snapshot** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **DB subnet group** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **DB parameter group** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

Nothing RDS-related exists in any layer. A `grep` for `rds` matches only
substrings in unrelated words (`records`, `forwards`, `standards`).

The `rds` client is not constructed anywhere, so this is the first
collector in the codebase to use it.

---

## 2. Scope decision

**This step implements DB instances only.**

Deferred, and recorded here rather than silently omitted:

| Deferred | Why it matters | Why not now |
|---|---|---|
| **DB clusters** | Aurora holds encryption and backup settings at the *cluster* level | Aurora member instances still appear in `DescribeDBInstances` and report `StorageEncrypted`, so instance-level collection is not wrong for Aurora — it is incomplete. A cluster collector is a clean follow-on |
| **DB snapshots** | A **public snapshot** is one of the highest-severity RDS findings — it exposes a full copy of the database | Separate API, separate lifecycle object, and a genuinely different resource type. Bundling it would double this step |
| **Subnet / parameter groups** | Parameter groups carry TLS-enforcement settings (`rds.force_ssl`) | Configuration objects, not resources an attacker reaches |

Being explicit: **collecting RDS instances but not snapshots means the
public-snapshot risk is invisible to this platform today.** That is a
real coverage gap, not a rounding error, and it is the first thing STEP
8C should close.

---

## 3. Relationships — mapping to the existing vocabulary

The enum is closed. Every proposed edge below reuses an existing type or
is refused.

### 3.1 `rds_db_instance --ATTACHED_TO--> security_group` ✅

```
source            rds_db_instance
target            security_group
relationship_type ATTACHED_TO  (existing)
semantics         Identical to ec2_instance --ATTACHED_TO--> security_group:
                  a security group is configuration bound to the
                  resource, not a route an attacker travels.
AWS evidence      DescribeDBInstances → DBInstances[].VpcSecurityGroups[]
                  {VpcSecurityGroupId, Status}
traversable       NO — informational
```

Exact reuse of the EC2 pattern, including the direction: the instance
declares its groups, so the instance emits the edge.

Only groups whose `Status` is `active` produce an edge. A group mid-
attach is not yet governing traffic, matching the internet-gateway
attachment rule from STEP 8A.

### 3.2 Subnet placement — **attributes only, no edge** ✅

`DBSubnetGroup.Subnets[].SubnetIdentifier` names real subnets, and STEP
8A now collects them. It is still not an edge, for two reasons:

1. **Direction.** Placement is containment (subnet → instance), but the
   instance is what declares it, and `BuildResourceGraph` always sources
   an edge from the declaring resource. The same problem STEP 8A solved
   for VPC→subnet by having the *VPC* emit it — which is not available
   here without the subnet collector calling `rds`.
2. **Consistency.** `ec2_instance` does not record `SubnetId` at all, so
   emitting placement for RDS and not EC2 would make "which workloads
   are in this subnet" answerable for half the estate — worse than not
   answerable, because it looks complete.

`vpc_id` and `subnet_ids` are recorded as attributes. `ec2.py`'s own
docstring set this precedent explicitly.

### 3.3 KMS key — **attribute only, no edge** ✅

`KmsKeyId` names a real, collected resource, and `kms_key --PROTECTS-->
rds_db_instance` would be semantically correct. It is still not emitted:
the *instance* declares the key, and an instance cannot emit an edge
sourced from the key. Emitting `rds --ATTACHED_TO--> kms_key` instead
would invert the security meaning — the key protects the database, not
the other way round.

Recorded as `kms_key_id`. A future step can add it properly from the KMS
side.

### 3.4 Read replicas / cluster membership — **refused for now**

`ReadReplicaDBInstanceIdentifiers` and `DBClusterIdentifier` name real
relationships, but no existing type expresses "is a replica of" without
distortion, and the cluster is not collected. Recorded as attributes.

**No new `RelationshipType` is added in this step.**

---

## 4. Resource role — the one analyzer-visible decision

`rds_db_instance` is **data-bearing**. Left unclassified it would be
`OTHER`: never an attack path target, never worth reaching. That would
mean collecting the production database and then treating it as
irrelevant to risk.

**Proposal: `rds_db_instance → ResourceRole.STORAGE`**, beside
`s3_bucket` and `azure_storage_account`.

This is not a new scenario — it lets existing, already-tested scenarios
see a resource type they should always have seen. Checked against each:

| Scenario | Fires for RDS? | Why |
|---|---|---|
| `internet_to_sensitive_data` | **No** | Requires `public_exposure_evidence`, which reads `public` / `bucket_policy_allows_public_access` / … — none of which RDS sets (§5) |
| `sensitive_data_flow_to_exposed_store` | **No** | Same requirement on the target |
| `internet_to_workload_to_identity_to_data` | **Possibly, and correctly** | If an IAM policy grants access to an RDS ARN, a public workload with that role reaching the production database is exactly the chain a CSPM exists to find |
| `public_identity_with_privilege` | No | Targets identities |
| `internet_to_exposed_workload` | No | Targets workloads |

So the classification adds no spurious paths and unlocks one genuinely
valuable chain. **Flagged prominently in the report** so it can be vetoed
— it is the only change here that alters analyzer output.

---

## 5. `PubliclyAccessible` — deliberately NOT mapped to `public`

The tempting shortcut is to normalize `PubliclyAccessible: true` to the
existing `public` attribute, so `internet_to_sensitive_data` fires
immediately.

**That would be wrong.** RDS `PubliclyAccessible` means the instance has
a publicly-resolvable endpoint. It does **not** mean anyone can connect —
the security group still gates every packet. A publicly-addressable
instance behind a closed security group is not exposed.

This is precisely the distinction the codebase already makes for EC2,
where `internet_to_exposed_workload` requires a public address **and**
unrestricted ingress, with the comment *"Both halves are required …
Reporting either alone is"* a false positive.

So `publicly_accessible` is recorded under its own name, and the
security group half arrives through the `ATTACHED_TO` edge — the same
two-part evidence the workload scenario already uses.

Mapping it to `public` would produce a critical finding for every
correctly-firewalled public-endpoint database in the estate.

---

## 6. Secrets

`DescribeDBInstances` returns `MasterUsername` but **never** the
password. The username is an identifier, not a credential, and is what a
"default admin username" check needs.

It is not caught by `redaction.py`'s markers (no `secret`, `password`,
`token`, …), which is correct — redacting it would break the check
without protecting anything.

No RDS field returns credential material.

---

## 7. Terraform

**Status: GAP DOCUMENTED, unchanged.** No `aws_db_instance` exists in
`terraform/`. Same posture as STEP 8A: infrastructure expansion belongs
to the dedicated validation step, so this collector is verified against
fakes modelled on documented response shapes and **has never run against
a real AWS account**.

---

## 8. Rules

No rule targets `rds_db_instance`. None is added here — the graph and
collector tests validate the integration without one, and a rule family
belongs to the cross-resource-rules step.

Fields collected that a future rule can consume directly:
`publicly_accessible`, `storage_encrypted`, `backup_retention_period`,
`deletion_protection`, `multi_az`, `iam_database_authentication_enabled`,
`auto_minor_version_upgrade`, `performance_insights_enabled`.

---

## 9. Plan

1. `normalize_rds_instance` + `RdsInstanceCollector` (first `rds` client).
2. `ATTACHED_TO` to active security groups; everything else attributes.
3. `rds_db_instance` → `STORAGE` in the role table.
4. Register in `AwsCollector`.
5. Collector, normalizer, graph and analyzer-impact tests.
6. `docs/architecture/aws-rds-collector.md`.
7. No Terraform, no rules, no new scenario.
