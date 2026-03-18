output "s3_bucket_name" {
  description = "Name of the S3 bucket for data lake storage"
  value       = module.storage.data_lake_bucket_id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for data lake storage"
  value       = module.storage.data_lake_bucket_arn
}

output "sqs_queue_url" {
  description = "URL of the SQS queue for security findings"
  value       = module.ingestion.queue_url
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue for security findings"
  value       = module.ingestion.queue_arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.security_processor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.security_processor.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = var.enable_sns_alerts ? module.alerting[0].topic_arn : null
}

output "glue_database_name" {
  description = "Name of the Glue database"
  value       = module.analytics.glue_database_name
}

output "athena_table_name" {
  description = "Name of the Athena table"
  value       = module.analytics.table_name
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup"
  value       = module.analytics.workgroup_name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "iam_role_arn" {
  description = "ARN of the IAM role for Lambda execution"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "data_lake_s3_path" {
  description = "S3 path for the data lake findings"
  value       = "s3://${module.storage.data_lake_bucket_id}/findings/"
}

output "athena_results_s3_path" {
  description = "S3 path for Athena query results"
  value       = "s3://${module.storage.athena_results_bucket_id}/results/"
}

output "deployment_summary" {
  description = "Summary of the deployed infrastructure"
  value = {
    region           = var.aws_region
    environment      = var.environment
    s3_bucket        = module.storage.data_lake_bucket_id
    sqs_queue        = module.ingestion.queue_url
    lambda_function  = aws_lambda_function.security_processor.function_name
    sns_topic        = var.enable_sns_alerts ? module.alerting[0].topic_arn : "Disabled"
    glue_database    = module.analytics.glue_database_name
    athena_table     = module.analytics.table_name
    deployment_time  = timestamp()
  }
}
