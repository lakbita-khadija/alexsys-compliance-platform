module "s3_test_resource" {
  source      = "./modules/s3_test_resource"
  name_prefix = var.name_prefix
}

module "network_test_resource" {
  source      = "./modules/network_test_resource"
  name_prefix = var.name_prefix
}

module "iam_test_resource" {
  source      = "./modules/iam_test_resource"
  name_prefix = var.name_prefix
}

module "kms_test_resource" {
  source      = "./modules/kms_test_resource"
  name_prefix = var.name_prefix
}

module "cloudtrail_test_resource" {
  source      = "./modules/cloudtrail_test_resource"
  name_prefix = var.name_prefix
}

module "ec2_test_resource" {
  source                         = "./modules/ec2_test_resource"
  name_prefix                    = var.name_prefix
  compliant_security_group_id    = module.network_test_resource.compliant_security_group_id
  noncompliant_security_group_id = module.network_test_resource.noncompliant_security_group_id
}
