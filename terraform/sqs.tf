# SQS Queue for Security Findings
resource "aws_sqs_queue" "security_findings" {
  name = local.sqs_queue_name
  
  # Queue configuration
  visibility_timeout_seconds = var.sqs_visibility_timeout
  message_retention_seconds  = var.sqs_message_retention
  delay_seconds             = 0
  receive_wait_time_seconds = 20 # Long polling
  
  # Dead letter queue configuration
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.security_findings_dlq.arn
    maxReceiveCount     = 3
  })
  
  tags = merge(local.common_tags, var.tags)
}

# SQS Dead Letter Queue
resource "aws_sqs_queue" "security_findings_dlq" {
  name = "${local.sqs_queue_name}-dlq"
  
  message_retention_seconds = 1209600 # 14 days
  delay_seconds             = 0
  receive_wait_time_seconds = 20
  
  tags = merge(local.common_tags, var.tags)
}

# SQS Queue Policy
resource "aws_sqs_queue_policy" "security_findings" {
  queue_url = aws_sqs_queue.security_findings.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaToReceiveMessages"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.security_findings.arn
      },
      {
        Sid    = "AllowSNSToSendMessages"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.security_findings.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = var.enable_sns_alerts ? aws_sns_topic.security_alerts[0].arn : "*"
          }
        }
      }
    ]
  })
}

# SQS Event Source Mapping for Lambda
resource "aws_lambda_event_source_mapping" "security_findings" {
  event_source_arn = aws_sqs_queue.security_findings.arn
  function_name    = aws_lambda_function.security_processor.arn
  
  # Event source mapping configuration
  batch_size                         = 1
  maximum_batching_window_in_seconds = 5
  enabled                           = true
  
  # Function response types
  function_response_types = ["ReportBatchItemFailures"]
  
  # Scaling configuration
  scaling_config {
    maximum_concurrency = 1000
  }
} 