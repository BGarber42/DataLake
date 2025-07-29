# AWS Glue Catalog Database
resource "aws_glue_catalog_database" "security_db" {
  name        = local.glue_db_name
  description = "Security findings database for data lake"
  
  catalog_id = data.aws_caller_identity.current.account_id
  
  tags = merge(local.common_tags, var.tags)
}

# AWS Glue Catalog Table
resource "aws_glue_catalog_table" "security_findings" {
  name          = local.athena_table
  database_name = aws_glue_catalog_database.security_db.name
  catalog_id    = data.aws_caller_identity.current.account_id
  
  description = "Security findings table for Athena queries"
  
  # Table properties
  table_type = "EXTERNAL_TABLE"
  
  # Storage descriptor
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.data_lake.id}/findings/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
    
    # SerDe information
    ser_de_info {
      name                  = "JsonSerDe"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      
      parameters = {
        "serialization.format" = "1"
      }
    }
    
    # Columns
    columns {
      name = "event_id"
      type = "string"
    }
    
    columns {
      name = "timestamp"
      type = "string"
    }
    
    columns {
      name = "severity"
      type = "string"
    }
    
    columns {
      name = "source"
      type = "string"
    }
    
    columns {
      name = "finding_type"
      type = "string"
    }
    
    columns {
      name = "description"
      type = "string"
    }
    
    columns {
      name = "affected_resources"
      type = "array<string>"
    }
    
    columns {
      name = "metadata"
      type = "struct<account_id:string,region:string,tags:map<string,string>>"
    }
    
    columns {
      name = "processed_at"
      type = "string"
    }
    
    columns {
      name = "partition_year"
      type = "string"
    }
    
    columns {
      name = "partition_month"
      type = "string"
    }
    
    columns {
      name = "partition_day"
      type = "string"
    }
  }
  
  # Partition keys
  partition_keys {
    name = "year"
    type = "string"
  }
  
  partition_keys {
    name = "month"
    type = "string"
  }
  
  partition_keys {
    name = "day"
    type = "string"
  }
  
  # Table parameters
  parameters = {
    "EXTERNAL"              = "TRUE"
    "projection.enabled"    = "true"
    "projection.year.type"  = "integer"
    "projection.year.range" = "2020,2030"
    "projection.month.type" = "integer"
    "projection.month.range" = "1,12"
    "projection.day.type"   = "integer"
    "projection.day.range"  = "1,31"
    "storage.location.template" = "s3://${aws_s3_bucket.data_lake.id}/findings/year=$${year}/month=$${month}/day=$${day}/"
  }
  
  tags = merge(local.common_tags, var.tags)
}

# Athena Workgroup
resource "aws_athena_workgroup" "security_workgroup" {
  name = "security-data-lake-workgroup"
  
  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    
    result_configuration {
      output_location = "s3://${aws_s3_bucket.data_lake.id}/athena-results/"
      
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
    
    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
  }
  
  tags = merge(local.common_tags, var.tags)
}

# IAM Policy for Athena Access
resource "aws_iam_role" "athena_execution_role" {
  name = "athena-execution-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "athena.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, var.tags)
}

# IAM Policy for Athena S3 Access
resource "aws_iam_role_policy" "athena_s3" {
  name = "athena-s3-policy"
  role = aws_iam_role.athena_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:ListMultipartUploadParts",
          "s3:AbortMultipartUpload",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.data_lake.arn,
          "${aws_s3_bucket.data_lake.arn}/*"
        ]
      }
    ]
  })
}

# IAM Policy for Athena Glue Access
resource "aws_iam_role_policy" "athena_glue" {
  name = "athena-glue-policy"
  role = aws_iam_role.athena_execution_role.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions"
        ]
        Resource = [
          aws_glue_catalog_database.security_db.arn,
          "${aws_glue_catalog_database.security_db.arn}/*"
        ]
      }
    ]
  })
}

# CloudWatch Log Group for Athena
resource "aws_cloudwatch_log_group" "athena_logs" {
  name              = "/aws/athena/${aws_athena_workgroup.security_workgroup.name}"
  retention_in_days = var.log_retention_days
  
  tags = merge(local.common_tags, var.tags)
}

# CloudWatch Alarm for Athena Query Failures
resource "aws_cloudwatch_metric_alarm" "athena_query_failures" {
  count = var.enable_cloudwatch_logs ? 1 : 0
  
  alarm_name          = "athena-query-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "QueryFailed"
  namespace           = "AWS/Athena"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Athena query failure rate"
  alarm_actions       = var.enable_sns_alerts ? [aws_sns_topic.security_alerts[0].arn] : []
  
  dimensions = {
    WorkGroup = aws_athena_workgroup.security_workgroup.name
  }
} 