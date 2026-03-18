variable "queue_name" {
  type = string
}

variable "visibility_timeout" {
  type    = number
  default = 360
}

variable "message_retention" {
  type    = number
  default = 1209600
}

variable "lambda_function_arn" {
  type = string
}

variable "lambda_role_arn" {
  type = string
}

variable "enable_sns_alerts" {
  type    = bool
  default = true
}

variable "sns_topic_arn" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ---------------------------------------------------------------------------
# SQS Queues
# ---------------------------------------------------------------------------
resource "aws_sqs_queue" "findings" {
  name                       = var.queue_name
  visibility_timeout_seconds = var.visibility_timeout
  message_retention_seconds  = var.message_retention
  delay_seconds              = 0
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.findings_dlq.arn
    maxReceiveCount     = 3
  })

  tags = var.tags
}

resource "aws_sqs_queue" "findings_dlq" {
  name                      = "${var.queue_name}-dlq"
  message_retention_seconds = 1209600
  delay_seconds             = 0
  receive_wait_time_seconds = 20
  tags                      = var.tags
}

resource "aws_sqs_queue_policy" "findings" {
  queue_url = aws_sqs_queue.findings.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambdaToReceiveMessages"
        Effect    = "Allow"
        Principal = { AWS = var.lambda_role_arn }
        Action    = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource  = aws_sqs_queue.findings.arn
      },
      {
        Sid       = "AllowSNSToSendMessages"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = ["sqs:SendMessage"]
        Resource  = aws_sqs_queue.findings.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = var.enable_sns_alerts ? var.sns_topic_arn : "*"
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Event Source Mapping
# ---------------------------------------------------------------------------
resource "aws_lambda_event_source_mapping" "findings" {
  event_source_arn                   = aws_sqs_queue.findings.arn
  function_name                      = var.lambda_function_arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 30
  enabled                            = true
  function_response_types            = ["ReportBatchItemFailures"]

  scaling_config {
    maximum_concurrency = 1000
  }
}

resource "aws_lambda_permission" "sqs_invoke" {
  statement_id  = "AllowSQSToInvokeLambda"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_arn
  principal     = "sqs.amazonaws.com"
  source_arn    = aws_sqs_queue.findings.arn
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "queue_url" {
  value = aws_sqs_queue.findings.url
}

output "queue_arn" {
  value = aws_sqs_queue.findings.arn
}

output "dlq_arn" {
  value = aws_sqs_queue.findings_dlq.arn
}
