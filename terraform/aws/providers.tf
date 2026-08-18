provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ComplianceIQ"
      Environment = var.environment
      Purpose     = "compliance-scanning-test-environment"
      ManagedBy   = "terraform"
      TenantId    = var.tenant_id
    }
  }
}
