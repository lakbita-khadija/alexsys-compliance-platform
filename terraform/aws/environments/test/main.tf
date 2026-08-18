# The actual deployable root for the ComplianceIQ AWS test
# environment. `terraform/aws/` (one level up) is a reusable module
# composing the five test-resource modules; this file is what you
# actually `terraform init`/`apply` from.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # No backend block: this test environment intentionally uses local
  # state (see ../../README.md, "Terraform State"). For anything
  # longer-lived than a demo, configure a remote backend here — never
  # commit terraform.tfstate either way (see the .gitignore in this
  # directory tree).
}

module "compliance_test_environment" {
  source = "../../"

  environment = var.environment
  aws_region  = var.aws_region
  tenant_id   = var.tenant_id
  name_prefix = var.name_prefix
}

output "compliant_bucket_name" {
  value = module.compliance_test_environment.compliant_bucket_name
}

output "noncompliant_bucket_name" {
  value = module.compliance_test_environment.noncompliant_bucket_name
}

output "compliant_security_group_id" {
  value = module.compliance_test_environment.compliant_security_group_id
}

output "noncompliant_security_group_id" {
  value = module.compliance_test_environment.noncompliant_security_group_id
}

output "noncompliant_iam_user_name" {
  value = module.compliance_test_environment.noncompliant_iam_user_name
}

output "noncompliant_full_admin_iam_user_name" {
  value = module.compliance_test_environment.noncompliant_full_admin_iam_user_name
}

output "compliant_kms_key_arn" {
  value = module.compliance_test_environment.compliant_kms_key_arn
}

output "noncompliant_kms_key_arn" {
  value = module.compliance_test_environment.noncompliant_kms_key_arn
}

output "policy_public_kms_key_arn" {
  value = module.compliance_test_environment.policy_public_kms_key_arn
}

output "cloudtrail_trail_arn" {
  value = module.compliance_test_environment.cloudtrail_trail_arn
}

output "policy_public_bucket_name" {
  value = module.compliance_test_environment.policy_public_bucket_name
}

output "chained_to_open_security_group_id" {
  value = module.compliance_test_environment.chained_to_open_security_group_id
}

output "compliant_ec2_instance_id" {
  value = module.compliance_test_environment.compliant_ec2_instance_id
}

output "noncompliant_ec2_instance_id" {
  value = module.compliance_test_environment.noncompliant_ec2_instance_id
}
