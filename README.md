# Serverless Security Data Lake

A production-ready serverless data platform for ingesting, processing, and analyzing security findings using AWS services. Data is stored as columnar **Parquet** for efficient, low-cost Athena queries.

## Architecture Overview

```
Security Findings ─► SQS Queue ─► Lambda (batch) ─► S3 (Parquet, partitioned) ─► Athena
                                       │
                                       └─► SNS (HIGH/CRITICAL alerts)
```

1. **Ingestion** — Security findings arrive as JSON on an SQS queue.
2. **Processing** — A Lambda function (triggered in batches of 10) validates, normalizes, and writes Parquet files to S3.
3. **Storage** — Parquet files land in S3 with Hive-style partitioning (`year=/month=/day=`), lifecycle-tiered to Intelligent-Tiering → Glacier.
4. **Analysis** — Amazon Athena queries the Glue-cataloged Parquet data via partition projection.
5. **Alerting** — HIGH/CRITICAL findings trigger SNS notifications.

## Ephemeral by Design

This project is **ephemeral** — provisioned on-demand and torn down when not in use to maintain zero idle costs and validate Infrastructure as Code.

```bash
cd terraform
terraform init
terraform apply     # provision
terraform destroy   # tear down when done
```

## Technology Stack

| Layer       | Technology                            |
|-------------|---------------------------------------|
| IaC         | Terraform ≥ 1.0 (modular)            |
| Ingestion   | Amazon SQS (with DLQ)                |
| Processing  | AWS Lambda (Python 3.14, awswrangler)|
| Storage     | Amazon S3 (Parquet, lifecycle-tiered) |
| Catalog     | AWS Glue                              |
| Query       | Amazon Athena (engine v3)             |
| Alerting    | Amazon SNS                            |
| CI/CD       | GitHub Actions                        |

## Project Structure

```
.
├── .github/workflows/
│   └── ci.yml                    # CI pipeline (lint, test, terraform validate)
├── src/lambda/
│   └── processor.py              # Lambda function (batch Parquet writer)
├── tests/
│   ├── conftest.py               # Shared fixtures
│   └── test_processor.py         # Unit tests (moto-based)
├── terraform/
│   ├── main.tf                   # Root config (provider, locals, Lambda, module wiring)
│   ├── variables.tf              # Input variables with validation
│   ├── outputs.tf                # Output values
│   └── modules/
│       ├── storage/main.tf       # S3 buckets, encryption, lifecycle
│       ├── ingestion/main.tf     # SQS queues, event source mapping
│       ├── analytics/main.tf     # Glue catalog, Athena workgroup
│       └── alerting/main.tf      # SNS topic, subscriptions, filters
├── examples/
│   ├── test-messages.json        # Sample security findings
│   └── athena-queries.sql        # Example Athena queries
├── scripts/
│   └── send-test-message.py      # CLI tool to send test findings
├── pyproject.toml                # Project metadata, deps, and tool config (uv-managed)
├── uv.lock                      # Locked dependency graph (committed)
├── requirements.txt              # Pinned runtime deps for Lambda packaging
└── README.md
```

## Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform ≥ 1.0
- Python 3.14+

### Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### Send Test Messages

```bash
python scripts/send-test-message.py --queue-url $(cd terraform && terraform output -raw sqs_queue_url)
```

### Query Data

Use the Athena queries in `examples/athena-queries.sql` or query via the AWS Console against the `security_db.security_findings` table.

### Tear Down

```bash
cd terraform
terraform destroy
```

## Development

This project uses [uv](https://docs.astral.sh/uv/) for dependency management to keep your system Python clean.

### Setup

```bash
uv sync        # creates .venv and installs all deps (runtime + dev)
```

### Run Tests

```bash
uv run pytest
uv run pytest --cov=src --cov-report=term-missing
```

### Lint & Format

```bash
uv run black --check .
uv run flake8 src/ tests/
uv run mypy src/
```

## Data Schema

### Input (Security Finding)

```json
{
  "event_id": "uuid-string",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "HIGH|MEDIUM|LOW|CRITICAL",
  "source": "aws-guardduty|aws-security-hub|aws-config|custom",
  "finding_type": "malware|unauthorized-access|data-exfiltration|...",
  "description": "Detailed description",
  "affected_resources": ["arn:aws:..."],
  "metadata": {
    "account_id": "123456789012",
    "region": "us-east-1",
    "tags": {"Environment": "production"}
  }
}
```

### Output (Parquet, partitioned)

- **Path**: `s3://bucket/findings/year=YYYY/month=MM/day=DD/*.parquet`
- **Format**: Parquet (Snappy compression via awswrangler)
- **Partition projection**: Enabled for zero-maintenance partition discovery

## Security

- IAM least-privilege policies per resource
- S3 bucket policies enforce server-side encryption (AES-256)
- Public access blocked on all buckets
- All API calls logged via CloudTrail

## License

This project is provided as-is for educational and demonstration purposes.
