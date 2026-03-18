variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 60
  
  validation {
    condition     = var.lambda_timeout >= 3 && var.lambda_timeout <= 900
    error_message = "Lambda timeout must be between 3 and 900 seconds."
  }
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 512
  
  validation {
    condition     = contains([128, 256, 512, 1024, 2048, 4096], var.lambda_memory_size)
    error_message = "Lambda memory size must be one of: 128, 256, 512, 1024, 2048, 4096."
  }
}

variable "sqs_visibility_timeout" {
  description = "SQS visibility timeout in seconds (must be >= 6x lambda_timeout to prevent duplicate processing)"
  type        = number
  default     = 360
  
  validation {
    condition     = var.sqs_visibility_timeout >= 0 && var.sqs_visibility_timeout <= 43200
    error_message = "SQS visibility timeout must be between 0 and 43200 seconds."
  }
}

variable "sqs_message_retention" {
  description = "SQS message retention period in seconds"
  type        = number
  default     = 1209600 # 14 days
  
  validation {
    condition     = var.sqs_message_retention >= 60 && var.sqs_message_retention <= 1209600
    error_message = "SQS message retention must be between 60 and 1209600 seconds."
  }
}

variable "s3_lifecycle_days" {
  description = "Number of days before moving S3 objects to IA storage"
  type        = number
  default     = 30
  
  validation {
    condition     = var.s3_lifecycle_days >= 1
    error_message = "S3 lifecycle days must be at least 1."
  }
}

variable "s3_glacier_days" {
  description = "Number of days before moving S3 objects to Glacier"
  type        = number
  default     = 90
  
  validation {
    condition     = var.s3_glacier_days > var.s3_lifecycle_days
    error_message = "Glacier transition days must be greater than IA transition days."
  }
}

variable "enable_sns_alerts" {
  description = "Enable SNS alerts for high-severity findings"
  type        = bool
  default     = true
}

variable "sns_email_endpoints" {
  description = "List of email addresses to receive SNS alerts"
  type        = list(string)
  default     = []
  
  validation {
    condition = alltrue([
      for email in var.sns_email_endpoints : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid."
  }
}

variable "enable_cloudwatch_logs" {
  description = "Enable CloudWatch logs for Lambda function"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 30
  
  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be one of the allowed values."
  }
}

variable "tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
} 