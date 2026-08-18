# ComplianceIQ AWS Test Environment

**This provisions REAL AWS resources that cost REAL money and includes
INTENTIONALLY INSECURE configuration.** Read this entire file before
running anything.

## What this is

A small, real AWS environment that exists for one purpose: giving
ComplianceIQ's `AwsCollector` and rule catalog something real to scan
and produce genuine findings against. It deliberately provisions both a
compliant and a non-compliant version of each resource type blueprint
§15 defines compliant/non-compliant pairs for, so a scan demonstrably
produces both `PASS` and `FAIL` findings — not just "always finds
something."

**This is a `ComplianceIQ TEST ENVIRONMENT`.** Every module is under
`modules/*_test_resource/`, every resource is tagged
`Purpose = compliance-scanning-test-environment`, and the `environment`
variable is hard-validated to the literal value `"test"` — Terraform
refuses to apply with any other value. This is a deliberate,
enforced guard against ever pointing this configuration at a
production AWS account.

## What gets created

| Resource | Compliant | Non-compliant |
|---|---|---|
| S3 bucket | private, encrypted, versioned, logged | **public (ACL), unencrypted**; a third bucket is **public via bucket policy** instead of ACL |
| Security group | HTTPS only, from within the VPC | **SSH (22) open to 0.0.0.0/0**; a third group is restrictive itself but **references (ALLOWS) the open group** |
| EC2 instance | no public IP, IMDSv2 required, encrypted root volume, IAM instance profile attached, attached to the compliant security group | **public IP, IMDSv2 optional, unencrypted root volume, no instance profile**, attached to the open security group |
| IAM user | *(no-MFA counterpart not provisioned — see below)* | **no MFA device**; a second user has **AdministratorAccess attached directly** |
| IAM account password policy | one account-wide policy, set to the compliant configuration (14-char minimum, symbols/numbers required, 90-day max age, 24-generation reuse prevention) | *(account-wide singleton — see below)* |
| KMS key | rotation enabled | **rotation disabled**; a third key has a **key policy granting access to any principal** |
| CloudTrail trail | multi-region, log validation enabled, logs to a versioned, non-public bucket | *(not provisioned — see below)* |

Three deliberate omissions, not oversights:
* **No compliant no-MFA-counterpart IAM user is created.** Registering
  a virtual MFA device requires an interactive TOTP/QR-code enrollment
  step no Terraform provider can automate.
* **The account password policy is a single, account-wide resource.**
  AWS only allows one password policy per account, so it is set to the
  compliant configuration; the non-compliant branches of
  `rules/aws/iam.yaml`'s password-policy rules are proven at the
  unit-test level (`tests/unit/infrastructure/test_aws_iam_collector.py`).
  Root-user MFA (`iam-root-account-mfa-disabled`) is likewise not
  something Terraform can provision either way — it reports the real
  account's actual root MFA state, whatever that is.
* **No non-compliant CloudTrail trail is created.** Running two trails
  in one account for the sake of a second example was judged not worth
  the extra cost/complexity; the trail-disabled/single-region cases are
  already proven at the unit-test level
  (`tests/unit/infrastructure/test_aws_cloudtrail_collector.py`).

No real data is ever stored in any bucket. No security group here
grants access to anything a human depends on — the EC2 instances exist
purely to be scanned, not to run any workload.

## AWS costs

Everything here is chosen to be cheap, but **not free**:

* 4 S3 buckets: negligible (empty buckets, no storage costs beyond
  pennies for request/list activity).
* 3 security groups: free.
* 2 EC2 instances (`t3.micro`): **~$0.02/hour combined** while
  running — this is the main new ongoing cost added in Phase 3B. Stop
  or destroy them when not actively scanning.
* 2 IAM users + 1 account password policy: free.
* 3 KMS keys: **~$1/month per key** while they exist (AWS bills KMS
  customer-managed keys per month, prorated) — the largest ongoing
  fixed cost if you leave the environment up.
* 1 CloudTrail trail + its S3 bucket: the trail itself is free for one
  copy of management events; S3 storage for the (small) log files is
  pennies.

Running `terraform destroy` (see below) as soon as you're done testing
keeps this to at most a few dollars even if left up for a while. Do not
leave it running indefinitely, and do not leave the EC2 instances
running longer than an active scan/demo session.

## KNOWN LIMITATION: EBS encryption-by-default

If the target account/region has "EBS encryption by default" enabled,
AWS silently encrypts the non-compliant EC2 instance's root volume
regardless of this module's `encrypted = false` setting — in that case
the `ec2-instance-root-volume-not-encrypted` finding for it will
legitimately not fire. This is the account's own stronger default
working as intended, not a defect in this module or the rule.

## Credentials

No credentials are ever read from or written to any file in this
directory tree. Authentication is entirely external to Terraform,
via the AWS provider's own default credential chain — the same chain
`infrastructure/cloud/aws/session.py` uses for the actual scan:
environment variables, a named profile (`AWS_PROFILE`), or an assumed
role. Configure exactly one of those before running `terraform apply`
here; see the AWS CLI/provider docs for `aws configure` or
`~/.aws/credentials` if you don't already have one set up.

## Deploying

```sh
cd terraform/aws/environments/test
cp terraform.tfvars.example terraform.tfvars   # then edit if needed — never commit this file

terraform init
terraform validate
terraform plan      # READ this output before continuing
terraform apply
```

`terraform apply` will prompt for confirmation and show you the exact
non-compliant resources it's about to create (an open security group,
a public bucket, etc.) — read the plan, don't rubber-stamp it.

## Destroying

```sh
cd terraform/aws/environments/test
terraform destroy
```

Do this as soon as you're done scanning — see "AWS costs" above.

## State

`terraform.tfstate`/`terraform.tfstate.*`, `*.tfvars` (except
`terraform.tfvars.example`), and `.terraform/` are all `.gitignore`'d
at the repository root — never commit them. State can contain resource
attribute values; treat it as sensitive. This configuration uses local
state by design (it's a short-lived demo environment) — if you need
this to persist across machines or CI runs, add a remote backend block
to `environments/test/main.tf` yourself; none is provided here.

## After deploying: running an actual scan

See `docs/architecture/phase-3-infrastructure.md` §11 ("How to deploy
the test environment") for the full, exact command sequence — Terraform
apply, the dev scan runner, unit tests, integration tests, and
Terraform destroy, in order.
