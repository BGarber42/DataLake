# SNS Topic for Security Alerts
resource "aws_sns_topic" "security_alerts" {
  count = var.enable_sns_alerts ? 1 : 0
  
  name = local.sns_topic_name
  
  # Topic configuration
  delivery_policy = jsonencode({
    http = {
      defaultHealthyRetryPolicy = {
        minDelayRetry     = 20
        maxDelayRetry     = 20
        numRetries        = 3
        numMaxDelayRetries = 0
        numNoDelayRetries = 0
        backoffFunction   = "linear"
      }
      disableSubscriptionOverrides = false
      defaultThrottlePolicy = {
        maxReceivesPerSecond = 1
      }
    }
  })
  
  tags = merge(local.common_tags, var.tags)
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "security_alerts" {
  count = var.enable_sns_alerts ? 1 : 0
  
  arn = aws_sns_topic.security_alerts[0].arn
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaToPublish"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_execution_role.arn
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts[0].arn
      },
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts[0].arn
      }
    ]
  })
}

# SNS Email Subscriptions
resource "aws_sns_topic_subscription" "email_subscriptions" {
  count = var.enable_sns_alerts && length(var.sns_email_endpoints) > 0 ? length(var.sns_email_endpoints) : 0
  
  topic_arn = aws_sns_topic.security_alerts[0].arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoints[count.index]
}

# CloudWatch Alarm for SNS Delivery Failures
resource "aws_cloudwatch_metric_alarm" "sns_delivery_failures" {
  count = var.enable_sns_alerts && var.enable_cloudwatch_logs ? 1 : 0
  
  alarm_name          = "sns-delivery-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfNotificationsFailed"
  namespace           = "AWS/SNS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "SNS notification delivery failures"
  
  dimensions = {
    TopicName = aws_sns_topic.security_alerts[0].name
  }
}

# CloudWatch Alarm for SNS Publish Failures
resource "aws_cloudwatch_metric_alarm" "sns_publish_failures" {
  count = var.enable_sns_alerts && var.enable_cloudwatch_logs ? 1 : 0
  
  alarm_name          = "sns-publish-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfPublishesFailed"
  namespace           = "AWS/SNS"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "SNS publish failures"
  
  dimensions = {
    TopicName = aws_sns_topic.security_alerts[0].name
  }
}

# SQS Queue for SNS Message Filtering (Optional)
resource "aws_sqs_queue" "high_severity_filter" {
  count = var.enable_sns_alerts ? 1 : 0
  
  name = "${local.sqs_queue_name}-high-severity-filter"
  
  # Queue configuration
  visibility_timeout_seconds = 30
  message_retention_seconds  = 1209600 # 14 days
  delay_seconds             = 0
  receive_wait_time_seconds = 20
  
  tags = merge(local.common_tags, var.tags)
}

# SNS Subscription for High Severity Filter
resource "aws_sns_topic_subscription" "high_severity_filter" {
  count = var.enable_sns_alerts ? 1 : 0
  
  topic_arn = aws_sns_topic.security_alerts[0].arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.high_severity_filter[0].arn
  
  filter_policy_scope = "MessageAttributes"
  
  filter_policy = jsonencode({
    severity = ["HIGH", "CRITICAL"]
  })
}

# SQS Queue Policy for High Severity Filter
resource "aws_sqs_queue_policy" "high_severity_filter" {
  count = var.enable_sns_alerts ? 1 : 0
  
  queue_url = aws_sqs_queue.high_severity_filter[0].id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSNSToSendMessages"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.high_severity_filter[0].arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.security_alerts[0].arn
          }
        }
      }
    ]
  })
} 