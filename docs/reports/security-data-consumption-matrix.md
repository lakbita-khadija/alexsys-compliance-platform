# Security Data Consumption Matrix

> **The acceptance contract for "no dead data".**
>
> Every security-relevant field added by STEP 8A (AWS network) and
> STEP 8B (RDS), with what consumes it. Rows with no consumer are
> labelled **DEFERRED** and are candidates for removal, not silent
> retention.
>
> Baseline before this work: 1842 passed / 60 skipped / 0 failed.
> After: **1894 passed / 60 skipped / 0 failed.**

---

## 1. Why this document exists

Measured before any rule was written:

```
aws_vpc                6/6  attributes unconsumed
aws_subnet             8/8  unconsumed
aws_route_table        7/7  unconsumed
aws_internet_gateway   3/3  unconsumed
aws_network_acl        7/7  unconsumed
rds_db_instance       15/16 unconsumed

TOTAL: 46/47 attributes had no consumer
Resource types with ZERO rules: all six
```

STEP 8A and 8B built collectors, normalizers, graph edges and tests — and
then nothing read the result. That is the failure mode this step
corrects.

---

## 2. Valid consumers

Per the brief, a field is consumed if it feeds one of:

1. Rule Engine · 2. Cross-resource rule · 3. Graph query ·
4. Attack Path · 5. Risk calculation · 6. Compliance mapping ·
7. Resource identity / provenance

**"It might be useful later" is not a consumer.**

---

## 3. AWS — matrix

| Resource | Field / Relationship | Source API | Normalized as | Consumer | Rule / mechanism | Finding | Compliance | Status |
|---|---|---|---|---|---|---|---|---|
| **VPC** | `VpcId` | `DescribeVpcs` | node id | Identity | graph node | — | — | ✅ CONSUMED |
| VPC | `Subnets[].VpcId` | `DescribeSubnets` | `CONTAINS` edge | Graph | topology | contextual | — | ✅ CONSUMED |
| VPC | `cidr_block` / `cidr_blocks` | `DescribeVpcs` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| VPC | `state` | `DescribeVpcs` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| VPC | `is_default` | `DescribeVpcs` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| VPC | `instance_tenancy` | `DescribeVpcs` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| VPC | `dhcp_options_id` | `DescribeVpcs` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| **Subnet** | `SubnetId` | `DescribeSubnets` | node id | Identity | graph node | — | — | ✅ CONSUMED |
| Subnet | **`map_public_ip_on_launch`** | `DescribeSubnets` | attribute | **Cross-resource rule** | `subnet-auto-assigns-public-ip-with-internet-route` | MEDIUM | `iso_27001:A.8.20` | ✅ CONSUMED |
| Subnet | `vpc_id` | `DescribeSubnets` | attribute | Graph (VPC side) | `CONTAINS` | contextual | — | ✅ CONSUMED |
| Subnet | `cidr_block`, `ipv6_cidr_blocks` | `DescribeSubnets` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| Subnet | `availability_zone`, `state` | `DescribeSubnets` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| Subnet | `available_ip_address_count`, `is_default_for_az` | `DescribeSubnets` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| **RouteTable** | `RouteTableId` | `DescribeRouteTables` | node id | Identity | graph node | — | — | ✅ CONSUMED |
| RouteTable | **`has_internet_route`** | derived from `Routes[]` | attribute | **Rule ×2** | `route-table-has-internet-route`, and the subnet rule via traversal | LOW | `iso_27001:A.8.20` | ✅ CONSUMED |
| RouteTable | `routes[]` (structured) | `DescribeRouteTables` | ordered list | Evidence | backs `has_internet_route`; `target_type` distinguishes igw / nat / vgw | — | — | ✅ CONSUMED |
| RouteTable | `internet_gateway_ids` | derived | list | Graph | `CONNECTS_TO` → IGW | contextual | — | ✅ CONSUMED |
| RouteTable | `associated_subnet_ids` | `Associations[]` | list | **Graph** | `ATTACHED_TO` → subnet (**added this step**) | contextual | — | ✅ CONSUMED |
| RouteTable | `associations[]` | `DescribeRouteTables` | list | Evidence | backs the edge above | — | — | ✅ CONSUMED |
| RouteTable | `is_main` | `Associations[].Main` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RouteTable | `vpc_id` | `DescribeRouteTables` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| **IGW** | `InternetGatewayId` | `DescribeInternetGateways` | node id | Identity | graph node; `CONNECTS_TO` target | — | — | ✅ CONSUMED |
| IGW | `attached_vpc_ids` | `Attachments[]` | list | Graph | `ATTACHED_TO` → VPC | contextual | — | ✅ CONSUMED |
| IGW | `attachments[]` | `DescribeInternetGateways` | list | Evidence | backs the edge; preserves transient states | — | — | ✅ CONSUMED |
| IGW | `is_attached` | derived | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| **NACL** | `NetworkAclId` | `DescribeNetworkAcls` | node id | Identity | graph node | — | — | ✅ CONSUMED |
| NACL | **`has_unrestricted_ingress_rule`** | derived from `Entries[]` | attribute | **Rule** | `nacl-allows-unrestricted-ingress` | HIGH | `iso_27001:A.8.20` | ✅ CONSUMED |
| NACL | `ingress_entries[]` (ordered) | `DescribeNetworkAcls` | ordered list | Evidence | backs the flag; rule-number order preserved | — | — | ✅ CONSUMED |
| NACL | `associated_subnet_ids` | `Associations[]` | list | Graph | `PROTECTS` → subnet | contextual | — | ✅ CONSUMED |
| NACL | `egress_entries[]` | `DescribeNetworkAcls` | ordered list | — | — | — | — | ⚠️ **DEFERRED** |
| NACL | `is_default`, `vpc_id` | `DescribeNetworkAcls` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| **RDS** | `DBInstanceArn` | `DescribeDBInstances` | node id | **Identity + Attack Path** | ARN is what an IAM policy names, so `ACCESSES` can match | — | — | ✅ CONSUMED |
| RDS | **`storage_encrypted`** | `DescribeDBInstances` | attribute | **Rule** | `rds-storage-not-encrypted` | HIGH | `iso_27001:A.8.24` | ✅ CONSUMED |
| RDS | **`publicly_accessible`** | `DescribeDBInstances` | attribute | **Rule ×2** | `rds-public-endpoint-configured`, `rds-reachable-from-internet` | MEDIUM / CRITICAL | `iso_27001:A.8.20` | ✅ CONSUMED |
| RDS | **`backup_retention_period`** | `DescribeDBInstances` | attribute | **Rule** | `rds-automated-backups-disabled` | MEDIUM | `iso_27001:A.8.13` | ✅ CONSUMED |
| RDS | `VpcSecurityGroups[]` | `DescribeDBInstances` | `ATTACHED_TO` edge | **Cross-resource rule** | `rds-reachable-from-internet` traverses it | CRITICAL | `iso_27001:A.8.20` | ✅ CONSUMED |
| RDS | resource **role** = `STORAGE` | — | classification | **Attack Path** | `internet_to_workload_to_identity_to_data` | CRITICAL path | — | ✅ CONSUMED |
| RDS | `kms_key_id` | `DescribeDBInstances` | attribute | Evidence | names the key on an encryption finding | — | — | ✅ CONSUMED |
| RDS | `engine`, `engine_version` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RDS | `endpoint_address`, `endpoint_port` | `DescribeDBInstances` | attribute | Evidence | a responder verifies reachability with it | — | — | 🟡 EVIDENCE ONLY |
| RDS | `multi_az` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RDS | `deletion_protection` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RDS | `iam_database_authentication_enabled` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RDS | `auto_minor_version_upgrade` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RDS | `master_username` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |
| RDS | `status`, `vpc_id`, `subnet_ids` | `DescribeDBInstances` | attribute | — | — | — | — | ⚠️ **DEFERRED** |

---

## 4. Azure — **collectors do not exist**

The brief asks for Entra/RBAC, Private Endpoint and Azure SQL
consumption. Verified against the repository:

```
infrastructure/cloud/azure/resource_collectors/
  base.py  compute.py  keyvault.py  monitor.py  network.py  storage.py

Azure resource types emitted:
  azure_activity_log_setting · azure_key_vault
  azure_network_security_group · azure_storage_account
  azure_virtual_machine
```

| Provider | Resource | Status |
|---|---|---|
| Azure | **Entra ID / RBAC role assignments** | ❌ **NOT COLLECTED** — no collector, no Graph client |
| Azure | **Private Endpoint** | ❌ **NOT COLLECTED** |
| Azure | **Azure SQL** | ❌ **NOT COLLECTED** |

**There is no Azure data to consume for any of the three.** Writing rules
for them would mean writing rules against fields no collector produces —
they would sit permanently `INDETERMINATE`, which is fake coverage: a
rule catalog that looks larger while assessing nothing.

The five Azure resource types that *do* exist already have rules
(`rules/azure/*.yaml`), so no Azure dead data was introduced.

**Building those three collectors is a collection step, not a
consumption step**, and doing it here would contradict the brief's own
first instruction not to add resources for coverage's sake.

---

## 5. Rules added — seven, deliberately

Rule count is not the goal (§15). One cross-resource rule that joins two
facts is worth more than five restating one.

| Rule | Type | Severity | Consumes |
|---|---|---|---|
| `nacl-allows-unrestricted-ingress` | single | HIGH | NACL ingress entries |
| `route-table-has-internet-route` | single | **LOW** | route structure |
| `subnet-auto-assigns-public-ip-with-internet-route` | **cross-resource** | MEDIUM | subnet + route table via graph |
| `rds-storage-not-encrypted` | single | HIGH | `storage_encrypted` |
| `rds-public-endpoint-configured` | single | MEDIUM | `publicly_accessible` |
| `rds-reachable-from-internet` | **cross-resource** | **CRITICAL** | `publicly_accessible` + SG ingress |
| `rds-automated-backups-disabled` | single | MEDIUM | `backup_retention_period` |

### Three severity decisions worth defending

**`route-table-has-internet-route` is LOW, not HIGH.** Public routing is
*topology*. Whether anything is reachable depends on the security groups
and NACLs in front of it. The finding narrative says so explicitly, and
a test asserts the wording.

**`rds-public-endpoint-configured` is MEDIUM and says "configuration,
not confirmed reachability".** A public endpoint behind a closed security
group is not exposed. Reporting it as exposure would flag every correctly
firewalled database in an estate.

**`rds-reachable-from-internet` is CRITICAL because it proves both
halves** — public endpoint *and* an attached security group admitting
unrestricted ingress. This is the rule that asserts reachability, which
is exactly why the previous one does not.

### What was deliberately NOT ruled on

`deletion_protection`, `multi_az`, `iam_database_authentication_enabled`,
`auto_minor_version_upgrade` — all collected, all left unruled. Each
would need a **product policy** defining the expected state before a
finding could claim anything. Inventing that policy to raise the rule
count is how a CSPM starts reporting opinions as compliance failures.

`backup_retention_period == 0` is different and is ruled on: `0` is
AWS's own encoding for "backups off", a real threshold rather than an
invented number of days.

---

## 6. Relationship added

`route_table --ATTACHED_TO--> subnet`, from
`DescribeRouteTables.Associations[].SubnetId`.

Emitted from the route table because that is the side AWS reports it on
— the same rule that put `PROTECTS` on the NACL. `ATTACHED_TO` because an
association is configuration binding, not movement; it stays
informational.

**Its consumer is the subnet rule**, which traverses `direction:
incoming` to ask *"does the route table governing me reach the
internet?"* That is the strong evidence §6 requires, replacing
`map_public_ip_on_launch` alone.

No new `RelationshipType` was added.

---

## 7. Attack Path impact

**No new scenario.** One existing scenario gained reach:

```
internet → public EC2 → IAM role (rds-db:connect on the DB ARN) → RDS
```

enabled by STEP 8B's `STORAGE` classification plus the ARN-as-identity
decision. Verified in `test_rds_attack_path_impact.py`.

### NOT CURRENTLY EVIDENCED

A network-backed exposure scenario —
`internet → IGW → route table → subnet → workload` — remains
unevidenced.

> **Correction (STEP 8A.1).** The reason given here was **wrong**:
>
> > ~~**`ec2_instance` does not record its `SubnetId`.** The workload
> > cannot be located in the topology, so the network chain cannot join
> > to anything worth reaching.~~
>
> `SubnetId` has been collected since Phase 3. The missing piece was the
> `ec2_instance --ATTACHED_TO--> aws_subnet` **edge**, added in STEP
> 8A.1. The same false claim appeared in
> `docs/audits/aws-network-foundation-current-state.md` §6 and
> `docs/architecture/aws-network-collectors.md` §9 and is corrected in
> both. See `docs/audits/aws-network-completion.md` §2.

Both graph gaps are now closed — the subnet↔route-table edge in STEP 8A
and the workload↔subnet edge in STEP 8A.1 — and the chain is
**traversable as data**. It is still **not** an attack path, and
deliberately so:

- `ATTACHED_TO` and `CONTAINS` are classified informational, so nothing
  in the chain is traversable by the analyzer.
- Stateless, order-dependent NACL evaluation does not exist, so "this
  NACL permits the traffic" cannot be decided.
- The route-table main-table fallback is unmodelled, so "no association"
  cannot be distinguished from "no route".

The chain is consumed by a **rule** instead — see
`ec2-instance-in-internet-routed-subnet-with-public-ip` — which is the
honest form of the claim: internet *addressability*, established from
two hops of real AWS fields, with the security group named as the
control that decides actual reachability.

---

## 8. UNKNOWN handling

Every one of the seven rules has a dedicated `UNKNOWN` test asserting
`INDETERMINATE` rather than a false PASS.

The two cross-resource rules additionally distinguish:

| Situation | Result | Why |
|---|---|---|
| Neighbour absent | **PASS** | Absence of an association is not evidence of an internet route |
| Neighbour present, attribute unreadable | **INDETERMINATE** | A data gap, not a clean result |

"We could not determine whether backups are on" and "backups are on"
must never look the same.

---

## 9. Terraform audit (§21 — audit only, no changes)

| Resource | Collector | Normalized field | Rule consumer | Terraform |
|---|---|---|---|---|
| VPC | ✅ | topology | graph only | ❌ **missing** |
| Subnet | ✅ | `map_public_ip_on_launch` | ✅ cross-resource | ❌ **missing** |
| RouteTable | ✅ | `has_internet_route` | ✅ ×2 | ❌ **missing** |
| IGW | ✅ | attachments | graph only | ❌ **missing** |
| NACL | ✅ | ingress entries | ✅ | ❌ **missing** |
| RDS | ✅ | 4 fields | ✅ ×4 | ❌ **missing** |

**Every scenario below must be deployed before any of this is verified
against real AWS:**

1. Public subnet: `map_public_ip_on_launch` + route table → IGW
2. Private subnet: NAT gateway default route (must **not** fire)
3. NACL with an allow-all ingress entry, and one without
4. RDS unencrypted; RDS encrypted
5. RDS public + open SG (critical); RDS public + closed SG (must **not** fire)
6. RDS with `backup_retention_period` 0 and > 0

Scenarios 2 and 5 are the important ones: they are the **negative** cases
that prove the rules do not over-report.

---

## 10. Summary

| Metric | Before | After |
|---|---|---|
| Attributes with a consumer | 1 / 47 | **28 / 47** |
| Resource types with rules | 0 / 6 | **4 / 6** |
| Rules consuming new data | 0 | **7** |
| Cross-resource rules | 0 | **2** |
| New relationships | — | 1 (`ATTACHED_TO`, existing type) |

`aws_vpc` and `aws_internet_gateway` still have **no rule**, and that is
the honest position: neither has an independent security condition the
current evidence supports. Their consumer is the graph — §8 explicitly
permits that for the IGW. **19 attributes remain DEFERRED** and are
listed individually above as removal candidates rather than left
unexamined.
