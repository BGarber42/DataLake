# Serverless Security Data Lake

A modern, production-ready serverless data platform for ingesting, processing, and analyzing security findings using AWS services.

## Architecture Overview

This system implements a fully serverless security data pipeline that ingests security findings via SQS, processes them with Lambda, stores them in S3 with optimal partitioning, and enables ad-hoc analysis through Amazon Athena.

### Data Flow

1. **Ingestion**: Security findings are sent as JSON messages to an SQS queue
2. **Processing**: Lambda functions are triggered by SQS messages and normalize the data
3. **Storage**: Processed data is stored in S3 with date-based partitioning for efficient querying
4. **Analysis**: Amazon Athena provides SQL query capabilities over the partitioned data
5. **Alerting**: High-severity findings trigger SNS notifications

## Ephemeral by Design Philosophy

This project is designed to be **ephemeral** - provisioned on-demand and torn down when not in use to maintain zero idle costs and demonstrate Infrastructure as Code (IaC) best practices.

### Workflow

```bash
# Provision the infrastructure
terraform init
terraform apply

# Test the system
# Send test messages to SQS and verify data flow

# Destroy when done
terraform destroy
```

### Benefits of Ephemeral Design

- **Zero Idle Costs**: No charges when the system is not in use
- **Clean Environment**: Each deployment starts with a fresh, clean state
- **IaC Validation**: Ensures all infrastructure is properly codified
- **Security**: Reduces attack surface by not maintaining persistent resources
- **Compliance**: Demonstrates ability to recreate environments from code

## Technology Stack

- **Cloud Provider**: AWS
- **Ingestion**: Amazon SQS (Standard Queue)
- **Processing**: AWS Lambda (Python 3.11)
- **Storage**: Amazon S3 (with intelligent tiering)
- **Query Engine**: Amazon Athena
- **Data Catalog**: AWS Glue
- **Alerting**: Amazon SNS
- **Infrastructure**: Terraform
- **Data Format**: JSON with Parquet optimization for Athena

## Project Structure

```
.
├── README.md                 # This documentation
├── architecture.md           # Detailed architecture diagram
├── terraform/
│   ├── main.tf              # Main Terraform configuration
│   ├── variables.tf         # Variable definitions
│   ├── outputs.tf           # Output values
│   ├── providers.tf         # Provider configuration
│   ├── s3.tf               # S3 bucket and policies
│   ├── sqs.tf              # SQS queue configuration
│   ├── lambda.tf           # Lambda function and IAM
│   ├── athena.tf           # Athena and Glue configuration
│   └── sns.tf              # SNS topic for alerts
├── src/
│   └── lambda/
│       └── processor.py     # Lambda function code
├── examples/
│   ├── test-messages.json   # Sample security findings
│   └── athena-queries.sql  # Example Athena queries
└── scripts/
    └── send-test-message.py # Script to send test messages
```

## Quick Start

### Prerequisites

- AWS CLI configured with appropriate permissions
- Terraform installed (version >= 1.0)
- Python 3.11+ (for local testing)

### Deployment

1. **Initialize Terraform**:
   ```bash
   cd terraform
   terraform init
   ```

2. **Review the plan**:
   ```bash
   terraform plan
   ```

3. **Deploy the infrastructure**:
   ```bash
   terraform apply
   ```

4. **Send test messages**:
   ```bash
   python ../scripts/send-test-message.py
   ```

5. **Query the data**:
   - Use the Athena queries in `examples/athena-queries.sql`
   - Access Athena through the AWS Console or CLI

### Cleanup

When you're done testing:

```bash
terraform destroy
```

## Data Schema

### Input Schema (Security Finding)

```json
{
  "event_id": "uuid-string",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "HIGH|MEDIUM|LOW",
  "source": "aws-guardduty|aws-security-hub|custom",
  "finding_type": "malware|unauthorized-access|data-exfiltration",
  "description": "Detailed description of the security finding",
  "affected_resources": ["arn:aws:ec2:region:account:instance/i-1234567890abcdef0"],
  "metadata": {
    "account_id": "123456789012",
    "region": "us-east-1",
    "tags": {"Environment": "production"}
  }
}
```

### Output Schema (Normalized)

The Lambda processor normalizes the data and stores it with the following structure:

- **Partitioning**: `s3://bucket/findings/year=YYYY/month=MM/day=DD/`
- **File Format**: JSON (one finding per file)
- **Naming**: `{event_id}.json`

## Monitoring and Alerting

- **CloudWatch Logs**: All Lambda executions are logged
- **CloudWatch Metrics**: SQS queue depth, Lambda duration, errors
- **SNS Alerts**: High-severity findings trigger immediate notifications
- **Athena Query History**: Track query performance and usage

## Security Considerations

- **IAM Least Privilege**: All resources use minimal required permissions
- **Encryption**: Data encrypted at rest and in transit
- **VPC**: Lambda functions can be configured to run in VPC if needed
- **Audit Logging**: All API calls logged via CloudTrail

## Cost Optimization

- **S3 Intelligent Tiering**: Automatically moves data to cost-effective storage
- **Athena Query Optimization**: Partitioned data reduces scan costs
- **Lambda Timeout**: Configured to prevent runaway executions
- **SQS Visibility Timeout**: Optimized for processing time

## Troubleshooting

### Common Issues

1. **Lambda Timeout**: Increase timeout in `lambda.tf`
2. **SQS Message Processing**: Check CloudWatch logs for errors
3. **Athena Query Failures**: Verify partition structure in S3
4. **Permission Errors**: Ensure IAM roles have correct permissions

### Debug Commands

```bash
# Check Lambda logs
aws logs tail /aws/lambda/security-data-processor --follow

# Monitor SQS queue
aws sqs get-queue-attributes --queue-url $(terraform output -raw sqs_queue_url)

# Test Athena query
aws athena start-query-execution --query-string "SELECT COUNT(*) FROM security_findings" --result-configuration OutputLocation=s3://your-bucket/athena-results/
```

## Contributing

This project follows Infrastructure as Code best practices:

1. All changes must be made through Terraform
2. Test changes with `terraform plan` before applying
3. Use consistent naming conventions
4. Document any new variables or outputs

## License

This project is provided as-is for educational and demonstration purposes. 