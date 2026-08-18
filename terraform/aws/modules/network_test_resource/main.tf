# Security group test resources: one compliant (restrictive) group, one
# intentionally insecure group. Matches blueprint §15's security_group
# module table: "règles restrictives" vs "0.0.0.0/0 sur port sensible".
#
# Uses the account's default VPC — no dedicated network is provisioned,
# keeping this module cheap and simple (blueprint Phase 3 brief §16:
# "avoid expensive or unnecessary infrastructure"). Neither group is
# attached to any instance; they exist purely to be scanned.

data "aws_vpc" "default" {
  default = true
}

# ---------------------------------------------------------------------
# Compliant: HTTPS only, from inside the VPC — never 0.0.0.0/0
# ---------------------------------------------------------------------

resource "aws_security_group" "compliant" {
  name        = "${var.name_prefix}-compliant"
  description = "ComplianceIQ test: restrictive ingress, HTTPS only from within the VPC"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTPS from within the VPC only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.default.cidr_block]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------
# Non-compliant: SSH open to the entire internet
#
# This is the deliberate misconfiguration the scanner is meant to
# catch (rules/aws/security_group.yaml:
# security-group-ssh-open-to-world). It is not attached to any running
# instance, so it grants no actual access to anything — only its
# configuration is under test. This environment is explicitly a
# ComplianceIQ security-testing environment (see ../../README.md); this
# rule must never be replicated in a real network.
# ---------------------------------------------------------------------

resource "aws_security_group" "noncompliant" {
  name        = "${var.name_prefix}-noncompliant"
  description = "ComplianceIQ test: INTENTIONALLY insecure — SSH open to 0.0.0.0/0"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "INTENTIONALLY insecure: SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------
# Chained-exposure group: its own rules look fine (HTTPS only, from a
# specific source group) but it grants access *to* the wide-open
# `noncompliant` group above via a security-group reference — the
# transitive-exposure case
# rules/aws/security_group.yaml:security-group-allows-another-open-security-group
# is built to catch. Exists purely to be scanned, like every other
# group in this module.
# ---------------------------------------------------------------------

resource "aws_security_group" "chained_to_open" {
  name        = "${var.name_prefix}-chained-to-open"
  description = "ComplianceIQ test: own rules are restrictive, but references the wide-open noncompliant group"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description     = "References the intentionally open security group — transitive exposure test"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.noncompliant.id]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
