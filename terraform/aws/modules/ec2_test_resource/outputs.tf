output "compliant_instance_id" {
  value = aws_instance.compliant.id
}

output "noncompliant_instance_id" {
  value = aws_instance.noncompliant.id
}
