output "compliant_bucket_name" {
  value = aws_s3_bucket.compliant.id
}

output "noncompliant_bucket_name" {
  value = aws_s3_bucket.noncompliant.id
}

output "policy_public_bucket_name" {
  value = aws_s3_bucket.policy_public.id
}
