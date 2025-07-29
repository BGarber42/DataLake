terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    # Uncomment and configure for remote state storage
    # bucket = "your-terraform-state-bucket"
    # key    = "security-data-lake/terraform.tfstate"
    # region = "us-east-1"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "security-data-lake"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "security-team"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Random string for unique resource names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Local values for consistent naming
locals {
  name_prefix = "security-data-lake"
  name_suffix = random_string.suffix.result
  
  # Common tags
  common_tags = {
    Project     = "security-data-lake"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "security-team"
  }
  
  # Resource names
  s3_bucket_name = "${local.name_prefix}-${local.name_suffix}"
  sqs_queue_name = "${local.name_prefix}-findings-queue"
  lambda_name    = "${local.name_prefix}-processor"
  sns_topic_name = "${local.name_prefix}-alerts"
  glue_db_name   = "security_db"
  athena_table   = "security_findings"
} 