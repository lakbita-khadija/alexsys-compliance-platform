# Phase 3 — Infrastructure Layer, Real AWS Collector, Terraform Test Environment

Status: **implemented**. This document explains what Phase 3 built, why
it's structured the way it is, and — as with Phases 1 and 2 — what it
honestly does not do. It does not restate the blueprint; see
`ComplianceIQ_Senior_Architecture_Blueprint.md` and the Phase 1/2 docs
for what came before.

## 1. Why Infrastructure exists

Domain decides what's true ("a public S3 bucket violates this rule").
Application decides the sequence ("collect, then build a graph, then
evaluate rules"). Neither knows how to actually ask AWS for a list of
S3 buckets — and neither should, because "how do I call `ListBuckets`"
is a fact about AWS's API, not a fact about compliance or about
orchestration. Infrastructure is where that third kind of knowledge
lives: concrete, technology-specific adapters that make the abstractions
Application already defined (`BaseCollector`, `LoadRuleCatalog`) real.

## 2. Why boto3 is allowed in Infrastructure but not in Application

`application/scanning/scan_cloud_account.py` depends only on
`BaseCollector`, an `ABC` it defines itself. `infrastructure/cloud/aws/collector.py`
is one concrete answer to that abstraction — a `boto3.Session` goes in,
`NormalizedResource`s come out. If `boto3` lived in `application/`
instead, adding Azure would mean changing `ScanCloudAccount` itself;
because it doesn't, Azure support is "write a new
`infrastructure/cloud/azure/collector.py`", zero changes to
`application/` or `domain/`. Verified, not just claimed — see §7 below
for the actual grep output.

## 3. What an adapter is

A concrete implementation of a port. `AwsCollector(BaseCollector)` and
`YamlRuleCatalog(LoadRuleCatalog)` are this phase's two adapters — the
first real, non-fake implementations either port has had since Phase 2
defined them.

## 4. How `AwsCollector` implements `BaseCollector`

```python
class AwsCollector(BaseCollector):
    def collect(self) -> tuple[NormalizedResource, ...]: ...
```

`BaseCollector` (`application/scanning/collector.py`) was **not
modified** — Phase 2 already defined exactly the shape needed.
`AwsCollector` orchestrates six per-service sub-collectors (S3, IAM
users, EC2 instances, Security Groups, CloudTrail, KMS), each isolated:
a permission denial collecting KMS keys does not prevent S3 buckets
from being collected (blueprint §6's `_safe()` pattern). Only if *every*
sub-collector fails does `collect()` raise — a signal that something
systemic (credentials, network, an account-wide policy) is wrong, not
just one service being inaccessible.

Tenant identity is supplied by the caller and never derived from the
AWS account itself (`AwsCollector.__init__(..., tenant_id: TenantId, ...)`)
— the account being scanned and the tenant it's scanned *as* are kept
deliberately independent, per the Phase 3 brief §8.

## 5. How AWS resources become `NormalizedResource`

Each sub-collector pairs with a normalizer
(`infrastructure/cloud/aws/normalizers/*.py`) that maps raw boto3
response data onto the *existing, unmodified* `NormalizedResource`
contract:

```
AWS ListBuckets / GetBucketEncryption / GetBucketAcl / ...
      -> S3Collector (infrastructure/cloud/aws/resource_collectors/s3.py)
      -> normalize_s3_bucket(...)
      -> NormalizedResource(
             resource_id=ResourceId(bucket_name),
             resource_type="s3_bucket",
             cloud_provider=CloudProvider.AWS,
             tenant_id=<supplied by caller>,
             region="eu-west-1",
             attributes={"encrypted": ..., "public": ..., ...},
             relationships=(),
             collected_at=<explicit clock>,
         )
```

No `domain/` field was added, renamed, or loosened to make this easier
— `attributes` is exactly the free-form mapping ADR-003 already
provides for this purpose.

One deliberate, documented restraint: exposure (`public: bool`) is
captured as a plain attribute, **not** a `PUBLICLY_EXPOSED` graph
relationship to blueprint §11's special `__internet__` node. That node
is only ever created by attack-path discovery, which Phase 2 correctly
left unimplemented (no algorithm is specified anywhere in the
blueprint) — `BuildResourceGraph` has no code path that creates it.
Emitting that relationship now would raise `GraphIntegrityViolation` on
every real public bucket instead of reporting it. Two relationship
types *are* emitted, because both target real, already-collected
resources: EC2 instance → security group (`ATTACHED_TO`) and security
group → referenced security group (`ALLOWS`, from `UserIdGroupPairs`).

## 6. How Terraform provisions the test environment

```
terraform/aws/environments/test/  (the deployable root)
      -> module "compliance_test_environment" { source = "../../" }
terraform/aws/                    (reusable root module)
      -> module "s3_test_resource"         (compliant + non-compliant bucket)
      -> module "network_test_resource"    (compliant + non-compliant security group)
      -> module "iam_test_resource"        (non-compliant IAM user — no MFA)
      -> module "kms_test_resource"        (compliant + non-compliant KMS key)
      -> module "cloudtrail_test_resource" (one compliant, multi-region trail)
```

`environment = "test"` is enforced by a Terraform `validation` block —
any other value fails `terraform plan` outright. Every resource is
tagged `Purpose = compliance-scanning-test-environment`. Full deploy/
destroy instructions and AWS cost estimates are in `terraform/aws/README.md`.

## 7. Why Terraform is not part of Domain/Application

Verified, not assumed:

```
find terraform -name "*.py"                                    -> no results
grep -rn "import infrastructure\|from infrastructure" domain/ application/  -> no results
grep -rn "import application\|from application" domain/        -> no results
grep -rEn "^\s*(import|from)\s+(boto3|botocore|yaml)" domain/ application/  -> no results
```

Terraform provisions the environment the scanner scans; it never
becomes a dependency of any Python layer, and no Python layer becomes a
dependency of it. The relationship is one of *sequence* (apply, then
scan), never *import*.

## 8. Runtime cloud scanning vs. future IaC scanning

This phase implements exactly one of these two capabilities:

```
Runtime cloud scanning (Phase 3, THIS)      IaC scanning (NOT built)
AWS API                                     Terraform source (.tf files)
  -> actual deployed resources                -> static analysis
  -> AwsCollector                              -> IaC finding
  -> NormalizedResource
```

`AwsCollector` never reads a `.tf` file. Every `NormalizedResource` it
produces comes from a live AWS API response — `ScanCloudAccount`
observes what AWS actually reports right now, not what Terraform
declared it should be. This distinction is the entire point of Phase 3:
proving ComplianceIQ inspects real, deployed state, not source code
that might not even match reality (a manual console change, a failed
apply, drift). Parsing `.tf` files and calling that "scanning" was
explicitly out of scope and was not done.

## 9. Credential security

* `AwsCredentialConfig` (`infrastructure/cloud/aws/credentials.py`) has
  **no fields** for `aws_access_key_id`/`aws_secret_access_key`/
  `aws_session_token` — long-lived keys cannot be expressed in this
  codebase at all, let alone hard-coded. Verified by test
  (`test_config_never_carries_raw_access_keys`, which inspects the
  dataclass's actual fields).
* Supported credential sources, in the Phase 3 brief's preferred order:
  boto3's default credential chain (env vars, shared credentials file,
  attached IAM role) via an optional named profile, and optional STS
  role assumption on top of it (`AwsSessionFactory._assume_role`).
  Nothing else.
* Temporary STS credentials (when role assumption is used) exist only
  as local variables inside `AwsSessionFactory._assume_role` for the
  duration of building a `boto3.Session` — never logged, never printed,
  never written to a file.
* Nothing in `infrastructure/`, `scripts/dev_scan_aws.py`, or
  `terraform/` ever calls `print`/`log` on a credential object.
* Terraform state and `*.tfvars` (except the checked-in
  `terraform.tfvars.example`) are `.gitignore`'d at the repository root
  — see the "Terraform" section added to `.gitignore` this phase.
* The IAM test user Terraform creates has zero attached policies and no
  Terraform-managed access key — the non-compliance under test is
  "missing MFA," not "has real permissions."

## 10. Unit vs. integration tests

* **Unit** (`tests/unit/infrastructure/`, 91 tests): every AWS call is a
  hand-built fake (`FakeS3Client`, `FakePaginator`, ...) — no network,
  no credentials, no AWS account. Covers normalization, pagination
  (multi-page combination proven explicitly), empty/malformed
  responses, every `AwsError` subclass, region handling (including
  IAM's global no-region case), and relationship extraction.
* **Integration** (`tests/integration/aws/`, 22 tests): the real
  production wiring (`AwsSessionFactory` → `AwsCollector` →
  `YamlRuleCatalog` → `ScanCloudAccount`) against a real, Terraform-applied
  AWS account. Gated by `COMPLIANCEIQ_AWS_INTEGRATION_TESTS=1` plus the
  terraform output values as env vars (`tests/integration/aws/conftest.py`
  documents the exact commands) — absent that, they collect and report
  as **skipped**, never as failed or as collection errors, so
  `pytest tests/ -q` and CI stay credential-free by default. This
  repository's sandbox has no AWS account, so these 22 tests are
  written and verified to import/collect cleanly, but have not been
  run against real AWS in this session — see Known Limitations.

## 11. How to deploy the test environment (and run a real scan)

```sh
# 1. Provision
cd terraform/aws/environments/test
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform validate
terraform plan
terraform apply

# 2. Run a real scan (dev runner — see §12 for why this isn't a CLI)
cd ../../../..
python3 scripts/dev_scan_aws.py --tenant-id complianceiq-test-tenant --region us-east-1

# 3. Confirm nothing broke
python3 -m pytest tests/unit -q

# 4. Run the AWS integration suite (see tests/integration/aws/conftest.py
#    for the full env var list)
export COMPLIANCEIQ_AWS_INTEGRATION_TESTS=1
export COMPLIANCEIQ_TEST_TENANT_ID=complianceiq-test-tenant
export COMPLIANCEIQ_TEST_REGION=us-east-1
export COMPLIANCEIQ_TEST_COMPLIANT_BUCKET=$(terraform -chdir=terraform/aws/environments/test output -raw compliant_bucket_name)
export COMPLIANCEIQ_TEST_NONCOMPLIANT_BUCKET=$(terraform -chdir=terraform/aws/environments/test output -raw noncompliant_bucket_name)
export COMPLIANCEIQ_TEST_COMPLIANT_SG_ID=$(terraform -chdir=terraform/aws/environments/test output -raw compliant_security_group_id)
export COMPLIANCEIQ_TEST_NONCOMPLIANT_SG_ID=$(terraform -chdir=terraform/aws/environments/test output -raw noncompliant_security_group_id)
export COMPLIANCEIQ_TEST_NONCOMPLIANT_IAM_USER=$(terraform -chdir=terraform/aws/environments/test output -raw noncompliant_iam_user_name)
export COMPLIANCEIQ_TEST_COMPLIANT_KMS_KEY_ARN=$(terraform -chdir=terraform/aws/environments/test output -raw compliant_kms_key_arn)
export COMPLIANCEIQ_TEST_NONCOMPLIANT_KMS_KEY_ARN=$(terraform -chdir=terraform/aws/environments/test output -raw noncompliant_kms_key_arn)
export COMPLIANCEIQ_TEST_CLOUDTRAIL_ARN=$(terraform -chdir=terraform/aws/environments/test output -raw cloudtrail_trail_arn)
python3 -m pytest tests/integration/aws -q
```

`scripts/dev_scan_aws.py` is what's used in step 2 because Presentation
(a real CLI or API) doesn't exist yet (blueprint §5, FUTURE) — see §12.

## 12. Destroying the test environment

```sh
cd terraform/aws/environments/test
terraform destroy
```

Do this promptly after testing — `terraform/aws/README.md` has the
per-resource AWS cost breakdown (mainly ~$1/month per KMS key while
they exist; everything else is pennies).

## 13. What Phase 4 should implement

Per the blueprint's own roadmap (§24), Phase 3's brief already
completed "Adaptateur AWS complet ... + pagination" for the six
resource types in scope here. Recommended next steps, in the order the
blueprint implies:

* **Azure adapter** (blueprint §7, §24 Phase 4) — `infrastructure/cloud/azure/`,
  implementing `BaseCollector` the same way `AwsCollector` does, with
  Azure-native concepts (subscription, resource group, managed
  identity) mapped into `attributes` rather than forced into
  AWS-shaped fields (ADR-008).
* **Remaining AWS resource types** RDS, EBS, VPC (blueprint §6 lists
  these as still FUTURE even after "Phase 3 complete" — this phase
  covered S3, IAM Users, EC2, Security Groups, CloudTrail, KMS only,
  matching the Phase 3 brief's explicit, bounded resource list).
* **Terraform integration test scenarios** beyond the one compliant/
  non-compliant pair per resource type already here (blueprint §16's
  broader scenario matrix — `attack-paths/`, `identity/least-privilege`,
  etc.).
* **`RiskFactors` derivation** — Phase 2's `EnrichRisk` still has no
  caller; once an authoritative raw-signal-to-factor mapping is
  specified, this is where it plugs in.
* **Attack-path discovery** — still unspecified by the blueprint; not
  Phase 4's job unless that specification arrives first.
* **Persistence** (`infrastructure/persistence/`) — `FindingRepositoryPort`
  (Phase 2) has no real implementation yet; this is what would provide
  one, and is also the prerequisite for real drift detection across
  scans (a real "previous snapshot" source).

Not recommended before those: FastAPI/Presentation, JWT, the AI Core
HTTP client — all explicitly deferred by the blueprint's own phase
ordering (§24: Phase 11, Phase 12).

## Known limitations (explicit, not silent)

* **The AWS integration suite has not been run against real AWS in this
  session.** This sandbox has no AWS account, no network path to AWS
  APIs, and no Terraform provider registry access (`terraform init`
  fails to reach `registry.terraform.io` — confirmed, not assumed).
  The 22 integration tests were written against the exact real
  production classes, verified to import and collect cleanly (they
  report as `skipped`, not errored, without the opt-in env vars), and
  reviewed carefully for API correctness — but "written and reviewed"
  is not "proven against real AWS." Running them for real, and fixing
  whatever a real AWS account's actual API responses reveal that a
  hand-built fake didn't anticipate, is the natural first thing to do
  with real credentials.
* **Terraform HCL is syntax-checked, not schema-validated.** `terraform fmt -check`
  passes cleanly across the whole tree (confirmed) — but full
  `terraform validate` needs the AWS provider plugin, which requires
  registry access this sandbox doesn't have. Run
  `terraform init && terraform validate` yourself before `apply`.
* **EC2 instances have no dedicated rule.** `Ec2Collector` and its
  normalizer are complete and tested, but `rules/aws/` has no
  `ec2_instance`-targeting rule — the blueprint gives no
  compliant/non-compliant guidance for EC2 instances specifically
  (only for their attached Security Groups, which do have rules).
  `AttackPath`-relevant EC2→SecurityGroup relationships are still
  collected regardless.
* **No VPC/subnet graph relationships.** `vpc_id`/`subnet_id` are
  captured as EC2 instance attributes, not graph edges — the closed
  `RelationshipType` vocabulary (blueprint §10) has no precedent for
  network-topology containment, and inventing one wasn't necessary for
  this phase's rules.
* **IAM Roles are not collected**, only IAM Users — matching the
  blueprint's own CURRENT/FUTURE split (§6: "IAM Roles ... FUTURE").
* **S3 "public" detection covers ACL grants only**, not bucket-policy-based
  public exposure — documented as a simplification in
  `infrastructure/cloud/aws/normalizers/s3.py`.
* **`unrestricted_ingress_ports` only enumerates single-port rules.** A
  port-range or "all traffic" (`-1`) rule open to 0.0.0.0/0 correctly
  sets `has_unrestricted_ingress = True` but does not expand into
  individual port numbers — avoids inventing a port-expansion
  heuristic for an unbounded range.
* **No compliant IAM user / no non-compliant CloudTrail trail** in the
  Terraform environment — both are deliberate, documented omissions
  (see `terraform/aws/README.md`): virtual MFA enrollment can't be
  Terraform-automated, and a second CloudTrail trail was judged not
  worth the extra cost for a case already proven at the unit-test
  level.
* **`.gitignore` and `pyproject.toml` were modified** (Phase 1/2 files)
  — the only two Phase 1/2 files touched this phase, both purely
  additive: `.gitignore` gained Terraform state/credential patterns,
  `pyproject.toml` gained the `boto3`/`PyYAML` runtime dependencies
  Infrastructure genuinely needs, the `aws_integration` pytest marker,
  and `application*`/`infrastructure*` in the package list (the same
  omission would have applied to `application*` after Phase 2, had
  packaging been exercised then). No behavior of any Phase 1/2 class
  changed.
