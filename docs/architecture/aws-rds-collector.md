# AWS RDS Collector

> DB instances (STEP 8B).
>
> Audit that preceded this:
> [aws-rds-current-state.md](../audits/aws-rds-current-state.md).

---

## 1. Pipeline

```
DescribeDBInstances  →  RdsInstanceCollector  →  normalize_rds_instance  →  rds_db_instance
   (rds client)                                                              └─ ATTACHED_TO → security_group
```

The first collector in this codebase to use the `rds` client. Everything
else follows the established per-service pattern: same base class, same
paginator use, same `translate_client_error` → `AwsCollectionError`
wrapping, so `AwsCollector` isolates a failure here exactly as it does
any other.

---

## 2. The decision this step turns on

> **`PubliclyAccessible` is NOT normalized to `public`.**

`public` is the cross-provider attribute the attack path analyzer reads
as *"internet-reachable"*
(`domain/attack_paths/classification.py::_PUBLIC_EXPOSURE_ATTRIBUTES`).
Mapping RDS onto it would have been one line and would have made
`internet_to_sensitive_data` fire immediately.

It would also have been wrong. `PubliclyAccessible: true` means the
instance has a **publicly-resolvable endpoint**. It does not mean anyone
can connect — the security group still gates every packet. A
publicly-addressable database behind a closed security group is not
exposed.

The result would be a **critical finding for every correctly firewalled
public-endpoint database in the estate**, delivered confidently. That is
worse than reporting nothing, because it trains a security team to
distrust the tool.

The codebase already draws this line for EC2, where
`internet_to_exposed_workload` requires a public address **and**
unrestricted ingress — *"Both halves are required … Reporting either
alone is"* a false positive. RDS gets identical treatment:

| Half | Where it comes from |
|---|---|
| public endpoint | `publicly_accessible` attribute |
| reachable through the firewall | `ATTACHED_TO` → security group |

Pinned by `test_publicly_accessible_is_not_mapped_to_public` and by four
analyzer tests asserting a public database alone produces **zero** paths.

---

## 3. Resource role: `STORAGE`

`rds_db_instance` is classified `ResourceRole.STORAGE`, beside
`s3_bucket` and `azure_storage_account`.

**This is the only change in STEP 8B that alters analyzer output.**

A managed database is data-bearing — that is simply what it is, and the
role table exists to state such facts. Left unclassified it would be
`OTHER`: never a target, never worth reaching. The platform would collect
the production database and then treat it as irrelevant to risk.

It is **not** a new scenario. It lets existing, already-tested scenarios
see a resource type they should always have seen:

| Scenario | Fires for RDS? | Why |
|---|---|---|
| `internet_to_sensitive_data` | **No** | Needs `public`-family attributes RDS deliberately does not set (§2) |
| `sensitive_data_flow_to_exposed_store` | **No** | Same requirement on the target |
| `internet_to_workload_to_identity_to_data` | **Yes, correctly** | See below |
| `public_identity_with_privilege` | No | Targets identities |
| `internet_to_exposed_workload` | No | Targets workloads |

### The chain this unlocks

```
internet → public EC2 → IAM role (rds-db:connect on the DB ARN) → production database
```

Before this classification the analyzer walked that entire chain and
discarded it at the last hop, because the endpoint was `OTHER`. That is
the flagship CSPM finding, and it now scores `CRITICAL` with
`target_role: storage`.

STEP 2's guard still holds for the new type: a role with `Resource: "*"`
produces **no** `ACCESSES` edge and therefore no path — asserted by
`test_a_wildcard_grant_does_not_manufacture_the_chain`.

### Why the ARN is the resource id

`resource_id` is `DBInstanceArn`, not `DBInstanceIdentifier`. An
identifier is unique only per region per account; the ARN is globally
unique **and is what an IAM policy names**. That is what lets STEP 2's
`ACCESSES` derivation match a policy's `Resource` against this node. With
the bare identifier the edge would never form and the chain above would
silently not exist.

---

## 4. Relationships

| Source | Target | Type | AWS evidence | Traversable |
|---|---|---|---|---|
| `rds_db_instance` | `security_group` | `ATTACHED_TO` | `DBInstances[].VpcSecurityGroups[]`, `Status == active` | ❌ informational |

Exact reuse of the EC2 pattern, including direction: the instance
declares its groups, so the instance emits the edge. Only `active`
attachments qualify — a group mid-attach is not yet governing traffic,
the same rule STEP 8A applied to internet gateway attachments.

**No new `RelationshipType` was added.**

### Deliberately NOT edges

| Reference | Why it stays an attribute |
|---|---|
| `DBSubnetGroup.Subnets[]` | Placement is containment (subnet → instance), but the *instance* declares it and `BuildResourceGraph` always sources an edge from the declaring resource. Also: `ec2_instance` records no `SubnetId`, so emitting placement for RDS alone would make "which workloads are in this subnet" answerable for half the estate — worse than unanswerable, because it looks complete |
| `KmsKeyId` | `kms_key --PROTECTS--> rds` is correct, but the instance cannot emit an edge sourced from the key. Emitting `rds --ATTACHED_TO--> kms_key` instead would invert the security meaning |
| `DBClusterIdentifier`, `ReadReplica*` | Real relationships, but no existing type expresses "is a replica of" without distortion, and clusters are not collected |

---

## 5. Normalized fields

**Exposure** — `publicly_accessible` · `endpoint_address` · `endpoint_port`

**Data protection** — `storage_encrypted` · `kms_key_id` ·
`performance_insights_enabled`

**Resilience** — `backup_retention_period` · `multi_az` ·
`deletion_protection`

**Access and maintenance** — `master_username` ·
`iam_database_authentication_enabled` · `auto_minor_version_upgrade` ·
`ca_certificate_identifier`

**Placement** — `vpc_id` · `subnet_ids` · `db_subnet_group_name` ·
`availability_zone`

**Topology (named, not traversable)** — `db_cluster_identifier` ·
`read_replica_source` · `read_replica_identifiers`

**Engine** — `engine` · `engine_version` · `status` · `instance_class`

Note `backup_retention_period: 0` is a real value meaning *backups are
off*, and must not be confused with "not collected".

---

## 6. Secrets

`DescribeDBInstances` returns `MasterUsername` but **never** the
password. The username is an identifier, and it is what a "master user
is still named `admin`" check needs.

It is deliberately not caught by `redaction.py`'s markers — redacting an
identifier would break that check while protecting nothing. A test
asserts no attribute this normalizer produces matches
`is_secret_key`, and a second asserts the redaction backstop would still
catch a password-shaped field if a future API version ever returned one.

---

## 7. Failure semantics

| Situation | Behaviour |
|---|---|
| `AccessDenied` | `AwsCollectionError`; `AwsCollector` isolates it, other collectors continue |
| Throttling | Same translation; `resilience.py` governs retry |
| Empty response | `()` — a determinate answer |
| Missing `DBSubnetGroup` / `Endpoint` | `None` attributes, no crash |
| Inactive or malformed security group entry | No edge |

---

## 8. Tests

| Area | Coverage |
|---|---|
| Exposure semantics | `publicly_accessible` not mapped to `public` · no exposure evidence · endpoint recorded |
| Role | `STORAGE` classification |
| Normalization | ARN identity · tenant/account/region/time · engine · data protection · resilience · `backup_retention_period: 0` · master username · placement-not-edges · tags · missing blocks · six boolean defaults |
| Relationships | active group · sorted · three inactive states · malformed · duplicates |
| Collector contract | happy path · `rds` client used · empty · missing key · pagination · AccessDenied · throttling · determinism |
| Secrets | no credential-shaped attribute · redaction backstop |
| Attack path impact | private DB → no path · public DB → no path · unencrypted public DB → no path · open SG alone → no path · **flagship chain found** · ARN in chain · wildcard grant refused · determinism |

**45 new tests.** Full suite: **1842 passed, 60 skipped, 0 failed**
(baseline 1796).

---

## 9. Limitations

1. **DB snapshots are not collected.** A **public snapshot** exposes a
   full copy of the database and is one of the highest-severity RDS
   findings. It is invisible to this platform today. This is the most
   significant gap and the first thing a follow-on step should close.
2. **DB clusters are not collected.** Aurora holds encryption and backup
   settings at the cluster level. Aurora member instances still appear
   in `DescribeDBInstances`, so Aurora coverage is incomplete rather
   than wrong.
3. **Parameter groups are not collected**, so TLS-enforcement settings
   (`rds.force_ssl`) cannot be checked.
4. **No rules consume the new fields.** `publicly_accessible`,
   `storage_encrypted`, `backup_retention_period`, `deletion_protection`,
   `multi_az`, `iam_database_authentication_enabled` and
   `auto_minor_version_upgrade` are all collected and all currently
   unused — a rule family belongs to the cross-resource-rules step.
5. **No Terraform**, so this has **never run against a real AWS
   account** — verified only against fakes modelled on documented
   response shapes, like every other AWS collector here.
6. **No KMS `PROTECTS` edge** (§4), so "which databases does this key
   protect" is not a graph query yet.
