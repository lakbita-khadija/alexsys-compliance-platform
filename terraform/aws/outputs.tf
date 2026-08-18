output "compliant_bucket_name" {
  description = "The compliant S3 bucket — private, encrypted, versioned, logged."
  value       = module.s3_test_resource.compliant_bucket_name
}

output "noncompliant_bucket_name" {
  description = "The intentionally non-compliant S3 bucket — public, unencrypted."
  value       = module.s3_test_resource.noncompliant_bucket_name
}

output "compliant_security_group_id" {
  description = "The restrictive security group."
  value       = module.network_test_resource.compliant_security_group_id
}

output "noncompliant_security_group_id" {
  description = "The security group with SSH open to 0.0.0.0/0."
  value       = module.network_test_resource.noncompliant_security_group_id
}

output "noncompliant_iam_user_name" {
  description = "The IAM user with no MFA device."
  value       = module.iam_test_resource.noncompliant_user_name
}

output "noncompliant_full_admin_iam_user_name" {
  description = "The IAM user with AdministratorAccess attached directly."
  value       = module.iam_test_resource.noncompliant_full_admin_user_name
}

output "compliant_kms_key_arn" {
  description = "The KMS key with rotation enabled."
  value       = module.kms_test_resource.compliant_key_arn
}

output "noncompliant_kms_key_arn" {
  description = "The KMS key with rotation disabled."
  value       = module.kms_test_resource.noncompliant_key_arn
}

output "policy_public_kms_key_arn" {
  description = "The KMS key with a public key policy."
  value       = module.kms_test_resource.policy_public_key_arn
}

output "cloudtrail_trail_arn" {
  description = "The compliant, multi-region CloudTrail trail."
  value       = module.cloudtrail_test_resource.trail_arn
}

output "policy_public_bucket_name" {
  description = "The S3 bucket exposed through its bucket policy (not its ACL)."
  value       = module.s3_test_resource.policy_public_bucket_name
}

output "chained_to_open_security_group_id" {
  description = "The security group whose own rules are restrictive but that references the wide-open noncompliant group."
  value       = module.network_test_resource.chained_to_open_security_group_id
}

output "compliant_ec2_instance_id" {
  description = "The hardened EC2 instance (no public IP, IMDSv2 required, encrypted root volume, instance profile attached)."
  value       = module.ec2_test_resource.compliant_instance_id
}

output "noncompliant_ec2_instance_id" {
  description = "The soft EC2 instance (public IP, IMDSv2 optional, unencrypted root volume, no instance profile)."
  value       = module.ec2_test_resource.noncompliant_instance_id
}
