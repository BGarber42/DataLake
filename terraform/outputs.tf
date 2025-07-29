output "s3_bucket_name" {
  description = "Name of the S3 bucket for data lake storage"
  value       = aws_s3_bucket.data_lake.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for data lake storage"
  value       = aws_s3_bucket.data_lake.arn
}

output "sqs_queue_url" {
  description = "URL of the SQS queue for security findings"
  value       = aws_sqs_queue.security_findings.url
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue for security findings"
  value       = aws_sqs_queue.security_findings.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.security_processor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.security_processor.arn
}

output "lambda_function_invoke_arn" {
  description = "Invocation ARN of the Lambda function"
  value       = aws_lambda_function.security_processor.invoke_arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  value       = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].arn : null
}

output "sns_topic_name" {
  description = "Name of the SNS topic for security alerts"
  value       = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].name : null
}

output "glue_database_name" {
  description = "Name of the Glue database"
  value       = aws_glue_catalog_database.security_db.name
}

output "athena_table_name" {
  description = "Name of the Athena table"
  value       = aws_glue_catalog_table.security_findings.name
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup"
  value       = aws_athena_workgroup.security_workgroup.name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for Lambda"
  value       = aws_cloudwatch_log_group.lambda_logs.arn
}

output "iam_role_arn" {
  description = "ARN of the IAM role for Lambda execution"
  value       = aws_iam_role.lambda_execution_role.arn
}

output "data_lake_s3_path" {
  description = "S3 path for the data lake"
  value       = "s3://${aws_s3_bucket.data_lake.id}/findings/"
}

output "athena_results_s3_path" {
  description = "S3 path for Athena query results"
  value       = "s3://${aws_s3_bucket.data_lake.id}/athena-results/"
}

output "deployment_summary" {
  description = "Summary of the deployed infrastructure"
  value = {
    region              = var.aws_region
    environment         = var.environment
    s3_bucket          = aws_s3_bucket.data_lake.id
    sqs_queue          = aws_sqs_queue.security_findings.url
    lambda_function    = aws_lambda_function.security_processor.function_name
    sns_topic          = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].arn : "Disabled"
    glue_database      = aws_glue_catalog_database.security_db.name
    athena_table       = aws_glue_catalog_table.security_findings.name
    deployment_time    = timestamp()
  }
}

output "test_commands" {
  description = "Commands to test the deployed infrastructure"
  value = {
    send_test_message = "aws sqs send-message --queue-url ${aws_sqs_queue.security_findings.url} --message-body '{\"event_id\":\"test-123\",\"timestamp\":\"2024-01-15T10:30:00Z\",\"severity\":\"HIGH\",\"source\":\"test\",\"finding_type\":\"test\",\"description\":\"Test finding\"}'",
    check_lambda_logs = "aws logs tail /aws/lambda/${aws_lambda_function.security_processor.function_name} --follow",
    list_s3_objects   = "aws s3 ls s3://${aws_s3_bucket.data_lake.id}/findings/ --recursive",
    test_athena_query = "aws athena start-query-execution --query-string 'SELECT COUNT(*) FROM ${aws_glue_catalog_database.security_db.name}.${aws_glue_catalog_table.security_findings.name}' --result-configuration OutputLocation=s3://${aws_s3_bucket.data_lake.id}/athena-results/ --work-group ${aws_athena_workgroup.security_workgroup.name}"
  }
} 