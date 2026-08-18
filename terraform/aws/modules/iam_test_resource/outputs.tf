output "noncompliant_user_name" {
  value = aws_iam_user.noncompliant_no_mfa.name
}

output "noncompliant_user_arn" {
  value = aws_iam_user.noncompliant_no_mfa.arn
}

output "noncompliant_full_admin_user_name" {
  value = aws_iam_user.noncompliant_full_admin.name
}

output "noncompliant_full_admin_user_arn" {
  value = aws_iam_user.noncompliant_full_admin.arn
}
