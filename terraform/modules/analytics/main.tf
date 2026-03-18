variable "glue_db_name" {
  type = string
}

variable "table_name" {
  type = string
}

variable "data_lake_bucket_id" {
  type = string
}

variable "data_lake_bucket_arn" {
  type = string
}

variable "athena_results_bucket_id" {
  type = string
}

variable "enable_cloudwatch_logs" {
  type    = bool
  default = true
}

variable "enable_sns_alerts" {
  type    = bool
  default = true
}

variable "sns_topic_arn" {
  type    = string
  default = ""
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Glue Catalog
# ---------------------------------------------------------------------------
resource "aws_glue_catalog_database" "db" {
  name        = var.glue_db_name
  description = "Security findings database for data lake"
  catalog_id  = data.aws_caller_identity.current.account_id
  tags        = var.tags
}

resource "aws_glue_catalog_table" "findings" {
  name          = var.table_name
  database_name = aws_glue_catalog_database.db.name
  catalog_id    = data.aws_caller_identity.current.account_id
  description   = "Security findings table (Parquet)"
  table_type    = "EXTERNAL_TABLE"

  storage_descriptor {
    location      = "s3://${var.data_lake_bucket_id}/findings/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      name                  = "ParquetHiveSerDe"
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns { name = "event_id"; type = "string" }
    columns { name = "timestamp"; type = "string" }
    columns { name = "severity"; type = "string" }
    columns { name = "source"; type = "string" }
    columns { name = "finding_type"; type = "string" }
    columns { name = "description"; type = "string" }
    columns { name = "affected_resources"; type = "array<string>" }
    columns { name = "metadata_account_id"; type = "string" }
    columns { name = "metadata_region"; type = "string" }
    columns { name = "metadata_tags"; type = "string" }
    columns { name = "processed_at"; type = "string" }
  }

  partition_keys { name = "year"; type = "string" }
  partition_keys { name = "month"; type = "string" }
  partition_keys { name = "day"; type = "string" }

  parameters = {
    "EXTERNAL"                      = "TRUE"
    "projection.enabled"            = "true"
    "projection.year.type"          = "integer"
    "projection.year.range"         = "2020,2035"
    "projection.month.type"         = "integer"
    "projection.month.range"        = "1,12"
    "projection.day.type"           = "integer"
    "projection.day.range"          = "1,31"
    "storage.location.template"     = "s3://${var.data_lake_bucket_id}/findings/year=$${year}/month=$${month}/day=$${day}/"
    "parquet.compression"           = "SNAPPY"
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Athena named query: deduplicated view
# SQS Standard is at-least-once, so retries can produce duplicate rows.
# This view keeps only the latest-processed copy of each event_id.
# ---------------------------------------------------------------------------
resource "aws_athena_named_query" "create_dedup_view" {
  name        = "create-dedup-view"
  database    = aws_glue_catalog_database.db.name
  workgroup   = aws_athena_workgroup.workgroup.name
  description = "Creates the deduplicated findings view — run once after first deploy"

  query = <<-SQL
    CREATE OR REPLACE VIEW ${var.table_name}_deduped AS
    SELECT *
    FROM (
      SELECT *,
             ROW_NUMBER() OVER (
               PARTITION BY event_id
               ORDER BY processed_at DESC
             ) AS _row_num
      FROM ${aws_glue_catalog_database.db.name}.${var.table_name}
    )
    WHERE _row_num = 1
  SQL
}

# ---------------------------------------------------------------------------
# Athena Workgroup
# ---------------------------------------------------------------------------
resource "aws_athena_workgroup" "workgroup" {
  name = "${var.glue_db_name}-workgroup"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${var.athena_results_bucket_id}/results/"
      encryption_configuration { encryption_option = "SSE_S3" }
    }

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# IAM for Athena
# ---------------------------------------------------------------------------
resource "aws_iam_role" "athena" {
  name = "${var.glue_db_name}-athena-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "athena.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "athena_s3" {
  name = "${var.glue_db_name}-athena-s3"
  role = aws_iam_role.athena.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket",
        "s3:ListBucketMultipartUploads", "s3:ListMultipartUploadParts",
        "s3:AbortMultipartUpload", "s3:PutObject"
      ]
      Resource = [var.data_lake_bucket_arn, "${var.data_lake_bucket_arn}/*"]
    }]
  })
}

resource "aws_iam_role_policy" "athena_glue" {
  name = "${var.glue_db_name}-athena-glue"
  role = aws_iam_role.athena.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "glue:GetDatabase", "glue:GetDatabases", "glue:GetTable",
        "glue:GetTables", "glue:GetPartition", "glue:GetPartitions"
      ]
      Resource = [aws_glue_catalog_database.db.arn, "${aws_glue_catalog_database.db.arn}/*"]
    }]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "athena" {
  name              = "/aws/athena/${aws_athena_workgroup.workgroup.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_metric_alarm" "query_failures" {
  count               = var.enable_cloudwatch_logs ? 1 : 0
  alarm_name          = "${var.glue_db_name}-athena-query-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "QueryFailed"
  namespace           = "AWS/Athena"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "Athena query failure rate"
  alarm_actions       = var.enable_sns_alerts ? [var.sns_topic_arn] : []
  dimensions          = { WorkGroup = aws_athena_workgroup.workgroup.name }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "glue_database_name" {
  value = aws_glue_catalog_database.db.name
}

output "table_name" {
  value = aws_glue_catalog_table.findings.name
}

output "workgroup_name" {
  value = aws_athena_workgroup.workgroup.name
}
