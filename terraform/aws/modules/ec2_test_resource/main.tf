# EC2 instance test resources (Phase 3B): one hardened (compliant)
# instance, one intentionally soft (non-compliant) instance. Matches
# the same compliant/non-compliant pair convention as every other
# module in this environment, covering the exposure/hardening facts
# collected by infrastructure/cloud/aws/resource_collectors/ec2.py and
# evaluated by rules/aws/ec2.yaml: public IP, IAM instance profile,
# IMDSv2, root volume encryption.
#
# COST NOTE (blueprint Phase 3B brief, Part O): two `t3.micro`
# instances, billed only while running. `terraform destroy` removes
# them; there is no reason to leave this module applied longer than a
# scan/demo session. Uses the account's default VPC (same convention
# as network_test_resource) — no dedicated network is provisioned.
#
# KNOWN LIMITATION: if the account/region has "EBS encryption by
# default" enabled, AWS silently encrypts the non-compliant instance's
# root volume regardless of `encrypted = false` below — in that case
# the `ec2-instance-root-volume-not-encrypted` finding for it will
# legitimately not fire. This is documented, not a bug: the account's
# own stronger default is working as intended.

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# ---------------------------------------------------------------------
# IAM instance profile for the compliant instance only — the
# non-compliant instance deliberately has none
# (ec2-instance-no-iam-instance-profile). Zero managed policies
# attached: this role exists only to prove the profile-attached case,
# not to grant any real permission.
# ---------------------------------------------------------------------

data "aws_iam_policy_document" "instance_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "compliant_instance_role" {
  name               = "${var.name_prefix}-ec2-compliant-role"
  path               = "/complianceiq-test/"
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role.json
}

resource "aws_iam_instance_profile" "compliant" {
  name = "${var.name_prefix}-ec2-compliant-profile"
  role = aws_iam_role.compliant_instance_role.name
}

# ---------------------------------------------------------------------
# Compliant instance: no public IP, IMDSv2 required, encrypted root
# volume, IAM instance profile attached, restrictive security group.
# ---------------------------------------------------------------------

resource "aws_instance" "compliant" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [var.compliant_security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.compliant.name
  associate_public_ip_address = false

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name = "${var.name_prefix}-ec2-compliant"
  }
}

# ---------------------------------------------------------------------
# Non-compliant instance: public IP, IMDSv2 optional (v1 allowed),
# unencrypted root volume, no instance profile, security group with
# SSH open to 0.0.0.0/0 — deliberately insecure on every axis
# rules/aws/ec2.yaml checks. Never used for anything but being scanned.
# ---------------------------------------------------------------------

resource "aws_instance" "noncompliant" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [var.noncompliant_security_group_id]
  associate_public_ip_address = true

  metadata_options {
    http_tokens   = "optional"
    http_endpoint = "enabled"
  }

  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "${var.name_prefix}-ec2-noncompliant"
  }
}
