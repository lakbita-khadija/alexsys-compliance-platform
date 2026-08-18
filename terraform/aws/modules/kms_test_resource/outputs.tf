output "compliant_key_arn" {
  value = aws_kms_key.compliant.arn
}

output "noncompliant_key_arn" {
  value = aws_kms_key.noncompliant.arn
}

output "policy_public_key_arn" {
  value = aws_kms_key.policy_public.arn
}
