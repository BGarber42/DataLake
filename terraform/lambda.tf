# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.lambda_name}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, var.tags)
}

# IAM Role for Lambda Execution
resource "aws_iam_role" "lambda_execution_role" {
  name = "${local.lambda_name}-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, var.tags)
}

# IAM Policy for Lambda Basic Execution
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# IAM Policy for Lambda SQS Access
resource "aws_iam_role_policy" "lambda_sqs" {
  name = "${local.lambda_name}-sqs-policy"
  role = aws_iam_role.lambda_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = [
          aws_sqs_queue.security_findings.arn,
          aws_sqs_queue.security_findings_dlq.arn
        ]
      }
    ]
  })
}

# IAM Policy for Lambda S3 Access
resource "aws_iam_role_policy" "lambda_s3" {
  name = "${local.lambda_name}-s3-policy"
  role = aws_iam_role.lambda_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data_lake.arn,
          "${aws_s3_bucket.data_lake.arn}/*"
        ]
      }
    ]
  })
}

# IAM Policy for Lambda SNS Access (conditional)
resource "aws_iam_role_policy" "lambda_sns" {
  count = var.enable_sns_alerts ? 1 : 0
  
  name = "${local.lambda_name}-sns-policy"
  role = aws_iam_role.lambda_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts[0].arn
      }
    ]
  })
}

# IAM Policy for Lambda CloudWatch Logs
resource "aws_iam_role_policy" "lambda_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  
  name = "${local.lambda_name}-logs-policy"
  role = aws_iam_role.lambda_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_logs.arn}:*"
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "security_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = local.lambda_name
  role            = aws_iam_role.lambda_execution_role.arn
  handler         = "processor.lambda_handler"
  runtime         = "python3.11"
  
  # Function configuration
  timeout     = var.lambda_timeout
  memory_size = var.lambda_memory_size
  
  # Environment variables
  environment {
    variables = {
      S3_BUCKET_NAME = aws_s3_bucket.data_lake.id
      SNS_TOPIC_ARN  = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].arn : ""
      LOG_LEVEL      = "INFO"
      ENVIRONMENT    = var.environment
    }
  }
  
  # Tags
  tags = merge(local.common_tags, var.tags)
  
  # Depends on IAM role and log group
  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_cloudwatch_log_group.lambda_logs
  ]
}

# Data source for Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src/lambda"
  output_path = "${path.module}/lambda_function.zip"
  
  depends_on = [
    aws_iam_role.lambda_execution_role
  ]
}

# Lambda Permission for SQS
resource "aws_lambda_permission" "sqs_invoke" {
  statement_id  = "AllowSQSToInvokeLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_processor.function_name
  principal     = "sqs.amazonaws.com"
  source_arn    = aws_sqs_queue.security_findings.arn
}

# CloudWatch Alarm for Lambda Errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  
  alarm_name          = "${local.lambda_name}-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Lambda function error rate"
  alarm_actions       = var.enable_sns_alerts ? [aws_sns_topic.security_alerts[0].arn] : []
  
  dimensions = {
    FunctionName = aws_lambda_function.security_processor.function_name
  }
}

# CloudWatch Alarm for Lambda Duration
resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  
  alarm_name          = "${local.lambda_name}-duration"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Average"
  threshold           = tostring(var.lambda_timeout * 1000 * 0.8) # 80% of timeout
  alarm_description   = "Lambda function execution duration"
  alarm_actions       = var.enable_sns_alerts ? [aws_sns_topic.security_alerts[0].arn] : []
  
  dimensions = {
    FunctionName = aws_lambda_function.security_processor.function_name
  }
} 