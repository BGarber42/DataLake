terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.20"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    # Uncomment and configure for remote state storage
    # bucket = "your-terraform-state-bucket"
    # key    = "security-data-lake/terraform.tfstate"
    # region = "us-east-1"
  }
}

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

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  name_prefix = "security-data-lake"
  name_suffix = random_string.suffix.result

  common_tags = {
    Project     = "security-data-lake"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "security-team"
  }

  s3_bucket_name = "${local.name_prefix}-${local.name_suffix}"
  sqs_queue_name = "${local.name_prefix}-findings-queue"
  lambda_name    = "${local.name_prefix}-processor"
  sns_topic_name = "${local.name_prefix}-alerts"
  glue_db_name   = "security_db"
  athena_table   = "security_findings"
}

# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------
module "storage" {
  source            = "./modules/storage"
  bucket_name       = local.s3_bucket_name
  s3_lifecycle_days = var.s3_lifecycle_days
  s3_glacier_days   = var.s3_glacier_days
  tags              = merge(local.common_tags, var.tags)
}

module "alerting" {
  count = var.enable_sns_alerts ? 1 : 0

  source                 = "./modules/alerting"
  topic_name             = local.sns_topic_name
  lambda_role_arn        = aws_iam_role.lambda_execution_role.arn
  email_endpoints        = var.sns_email_endpoints
  queue_name             = local.sqs_queue_name
  enable_cloudwatch_logs = var.enable_cloudwatch_logs
  tags                   = merge(local.common_tags, var.tags)
}

module "ingestion" {
  source              = "./modules/ingestion"
  queue_name          = local.sqs_queue_name
  visibility_timeout  = var.sqs_visibility_timeout
  message_retention   = var.sqs_message_retention
  lambda_function_arn = aws_lambda_function.security_processor.arn
  lambda_role_arn     = aws_iam_role.lambda_execution_role.arn
  enable_sns_alerts   = var.enable_sns_alerts
  sns_topic_arn       = var.enable_sns_alerts ? module.alerting[0].topic_arn : ""
  tags                = merge(local.common_tags, var.tags)
}

module "analytics" {
  source                   = "./modules/analytics"
  glue_db_name             = local.glue_db_name
  table_name               = local.athena_table
  data_lake_bucket_id      = module.storage.data_lake_bucket_id
  data_lake_bucket_arn     = module.storage.data_lake_bucket_arn
  athena_results_bucket_id = module.storage.athena_results_bucket_id
  enable_cloudwatch_logs   = var.enable_cloudwatch_logs
  enable_sns_alerts        = var.enable_sns_alerts
  sns_topic_arn            = var.enable_sns_alerts ? module.alerting[0].topic_arn : ""
  log_retention_days       = var.log_retention_days
  tags                     = merge(local.common_tags, var.tags)
}

# ---------------------------------------------------------------------------
# Lambda (remains at root — orchestrates between all modules)
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.lambda_name}"
  retention_in_days = var.log_retention_days
  tags              = merge(local.common_tags, var.tags)
}

resource "aws_iam_role" "lambda_execution_role" {
  name = "${local.lambda_name}-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = merge(local.common_tags, var.tags)
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_sqs" {
  name = "${local.lambda_name}-sqs-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
      Resource = [module.ingestion.queue_arn, module.ingestion.dlq_arn]
    }]
  })
}

resource "aws_iam_role_policy" "lambda_s3" {
  name = "${local.lambda_name}-s3-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
      Resource = [module.storage.data_lake_bucket_arn, "${module.storage.data_lake_bucket_arn}/*"]
    }]
  })
}

resource "aws_iam_role_policy" "lambda_sns" {
  count = var.enable_sns_alerts ? 1 : 0
  name  = "${local.lambda_name}-sns-policy"
  role  = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sns:Publish"]
      Resource = module.alerting[0].topic_arn
    }]
  })
}

resource "aws_iam_role_policy" "lambda_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  name  = "${local.lambda_name}-logs-policy"
  role  = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
    }]
  })
}

data "aws_ssm_parameter" "awswrangler_layer" {
  name = "/aws/service/aws-sdk-pandas/python3.14/x86_64/layer-arn"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src/lambda"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_lambda_function" "security_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = local.lambda_name
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "processor.lambda_handler"
  runtime          = "python3.14"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory_size

  layers = [data.aws_ssm_parameter.awswrangler_layer.value]

  environment {
    variables = {
      S3_BUCKET_NAME = module.storage.data_lake_bucket_id
      SNS_TOPIC_ARN  = var.enable_sns_alerts ? module.alerting[0].topic_arn : ""
      LOG_LEVEL      = "INFO"
      ENVIRONMENT    = var.environment
    }
  }

  tags = merge(local.common_tags, var.tags)

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_cloudwatch_log_group.lambda_logs,
  ]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count               = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name          = "${local.lambda_name}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Lambda function error rate"
  alarm_actions       = var.enable_sns_alerts ? [module.alerting[0].topic_arn] : []
  dimensions          = { FunctionName = aws_lambda_function.security_processor.function_name }
}

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  count               = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name          = "${local.lambda_name}-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = tostring(var.lambda_timeout * 1000 * 0.8)
  alarm_description   = "Lambda function execution duration"
  alarm_actions       = var.enable_sns_alerts ? [module.alerting[0].topic_arn] : []
  dimensions          = { FunctionName = aws_lambda_function.security_processor.function_name }
}
