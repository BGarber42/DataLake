variable "topic_name" {
  type = string
}

variable "lambda_role_arn" {
  type = string
}

variable "email_endpoints" {
  type    = list(string)
  default = []
}

variable "queue_name" {
  type = string
}

variable "enable_cloudwatch_logs" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

# ---------------------------------------------------------------------------
# SNS Topic
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = var.topic_name

  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayRetry      = 20
        maxDelayRetry      = 20
        numRetries         = 3
        numMaxDelayRetries = 0
        numNoDelayRetries  = 0
        backoffFunction    = "linear"
      }
      disableSubscriptionOverrides = false
      defaultThrottlePolicy        = { maxReceivesPerSecond = 1 }
    }
  })

  tags = var.tags
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowLambdaToPublish"
        Effect    = "Allow"
        Principal = { AWS = var.lambda_role_arn }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      },
      {
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Email subscriptions
# ---------------------------------------------------------------------------
resource "aws_sns_topic_subscription" "email" {
  count     = length(var.email_endpoints)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.email_endpoints[count.index]
}

# ---------------------------------------------------------------------------
# High-severity SQS filter
# ---------------------------------------------------------------------------
resource "aws_sqs_queue" "high_severity" {
  name                       = "${var.queue_name}-high-severity-filter"
  visibility_timeout_seconds = 30
  message_retention_seconds  = 1209600
  delay_seconds              = 0
  receive_wait_time_seconds  = 20
  tags                       = var.tags
}

resource "aws_sns_topic_subscription" "high_severity" {
  topic_arn           = aws_sns_topic.alerts.arn
  protocol            = "sqs"
  endpoint            = aws_sqs_queue.high_severity.arn
  filter_policy_scope = "MessageAttributes"
  filter_policy       = jsonencode({ severity = ["HIGH", "CRITICAL"] })
}

resource "aws_sqs_queue_policy" "high_severity" {
  queue_url = aws_sqs_queue.high_severity.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowSNSToSendMessages"
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.high_severity.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.alerts.arn } }
    }]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch alarms
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "delivery_failures" {
  count               = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name          = "${var.topic_name}-delivery-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfNotificationsFailed"
  namespace           = "AWS/SNS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "SNS notification delivery failures"
  dimensions          = { TopicName = aws_sns_topic.alerts.name }
}

resource "aws_cloudwatch_metric_alarm" "publish_failures" {
  count               = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name          = "${var.topic_name}-publish-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfPublishesFailed"
  namespace           = "AWS/SNS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "SNS publish failures"
  dimensions          = { TopicName = aws_sns_topic.alerts.name }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "topic_name" {
  value = aws_sns_topic.alerts.name
}
