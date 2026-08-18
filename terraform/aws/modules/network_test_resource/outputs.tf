output "compliant_security_group_id" {
  value = aws_security_group.compliant.id
}

output "noncompliant_security_group_id" {
  value = aws_security_group.noncompliant.id
}

output "chained_to_open_security_group_id" {
  value = aws_security_group.chained_to_open.id
}
