"""
Security Data Lake Lambda Processor

Processes security findings from SQS, normalizes the data, and writes
batched Parquet files to S3 with date-based partitioning for efficient Athena queries.

Deduplication strategy:
  SQS Standard provides at-least-once delivery. This processor writes Parquet files
  in append mode, so retries can produce duplicate rows. Consumers should query the
  deduplicated Athena view (`security_findings_deduped`) which uses ROW_NUMBER()
  over event_id to keep only the latest-processed copy of each finding.
"""

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Set, Tuple

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")

S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SOURCE_TYPES = ["aws-guardduty", "aws-security-hub", "aws-config", "custom"]
FINDING_TYPES = [
    "malware",
    "unauthorized-access",
    "data-exfiltration",
    "privilege-escalation",
    "network-attack",
    "credential-compromise",
    "compliance-violation",
    "other",
]


class SecurityFindingProcessor:
    """Processes, normalizes, and stores security findings as batched Parquet."""

    def __init__(self) -> None:
        self.s3_bucket = S3_BUCKET_NAME
        self.sns_topic_arn = SNS_TOPIC_ARN
        self.environment = ENVIRONMENT

    def validate_finding(self, finding: Dict[str, Any]) -> bool:
        required_fields = [
            "event_id",
            "timestamp",
            "severity",
            "source",
            "finding_type",
            "description",
        ]

        for field in required_fields:
            if field not in finding:
                logger.error(f"Missing required field: {field}")
                return False

        if finding["severity"] not in SEVERITY_LEVELS:
            logger.error(f"Invalid severity level: {finding['severity']}")
            return False

        if finding["source"] not in SOURCE_TYPES:
            logger.warning(f"Unknown source type: {finding['source']}")

        if finding["finding_type"] not in FINDING_TYPES:
            logger.warning(f"Unknown finding type: {finding['finding_type']}")

        try:
            datetime.fromisoformat(finding["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            logger.error(f"Invalid timestamp format: {finding['timestamp']}")
            return False

        return True

    def normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.fromisoformat(finding["timestamp"].replace("Z", "+00:00"))

        metadata = finding.get("metadata", {})
        if "account_id" not in metadata:
            metadata["account_id"] = "unknown"
        if "region" not in metadata:
            metadata["region"] = "unknown"
        if "tags" not in metadata:
            metadata["tags"] = {}

        return {
            "event_id": finding["event_id"],
            "timestamp": finding["timestamp"],
            "severity": finding["severity"].upper(),
            "source": finding["source"].lower(),
            "finding_type": finding["finding_type"].lower(),
            "description": finding["description"],
            "affected_resources": finding.get("affected_resources", []),
            "metadata_account_id": metadata["account_id"],
            "metadata_region": metadata["region"],
            "metadata_tags": json.dumps(metadata.get("tags", {})),
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "year": str(timestamp.year),
            "month": f"{timestamp.month:02d}",
            "day": f"{timestamp.day:02d}",
        }

    def store_findings_by_partition(
        self, findings: List[Dict[str, Any]]
    ) -> Tuple[Set[str], Set[str]]:
        """
        Write findings as Parquet, grouped by partition (year/month/day).

        Each partition is written independently so a failure in one partition
        does not force a retry of findings that were already persisted.

        Returns:
            (succeeded_event_ids, failed_event_ids)
        """
        partitions: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            key = f"{f['year']}/{f['month']}/{f['day']}"
            partitions[key].append(f)

        succeeded: Set[str] = set()
        failed: Set[str] = set()

        for partition_key, group in partitions.items():
            event_ids = {f["event_id"] for f in group}
            if self._write_partition(group):
                succeeded |= event_ids
            else:
                if self._store_findings_json_fallback(group):
                    succeeded |= event_ids
                else:
                    failed |= event_ids

        return succeeded, failed

    def _write_partition(self, findings: List[Dict[str, Any]]) -> bool:
        """Write a single partition's findings as one Parquet file."""
        try:
            import awswrangler as wr
            import pandas as pd

            df = pd.DataFrame(findings)
            df["affected_resources"] = df["affected_resources"].apply(
                lambda x: x if isinstance(x, list) else []
            )

            path = f"s3://{self.s3_bucket}/findings/"
            wr.s3.to_parquet(
                df=df,
                path=path,
                dataset=True,
                partition_cols=["year", "month", "day"],
                mode="append",
                boto3_session=boto3.Session(),
            )

            event_ids = [f["event_id"] for f in findings]
            logger.info(f"Wrote {len(df)} findings as Parquet ({event_ids})")
            return True

        except Exception as e:
            logger.error(f"Parquet write failed for partition: {e}")
            return False

    def _store_findings_json_fallback(self, findings: List[Dict[str, Any]]) -> bool:
        """Fallback: write each finding as individual JSON (deterministic key = idempotent)."""
        success = True
        for finding in findings:
            try:
                s3_key = (
                    f"findings/year={finding['year']}/month={finding['month']}"
                    f"/day={finding['day']}/{finding['event_id']}.json"
                )
                s3_client.put_object(
                    Bucket=self.s3_bucket,
                    Key=s3_key,
                    Body=json.dumps(finding, indent=2),
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                )
                logger.info(f"Fallback: stored {finding['event_id']} as JSON")
            except ClientError as e:
                logger.error(f"Fallback store failed for {finding['event_id']}: {e}")
                success = False
        return success

    def send_alert(self, finding: Dict[str, Any]) -> bool:
        if not self.sns_topic_arn or finding["severity"] not in ["HIGH", "CRITICAL"]:
            return True

        try:
            subject = f"Security Alert: {finding['severity']} {finding['finding_type']}"
            message = {
                "event_id": finding["event_id"],
                "severity": finding["severity"],
                "source": finding["source"],
                "finding_type": finding["finding_type"],
                "description": finding["description"],
                "timestamp": finding["timestamp"],
                "affected_resources": finding["affected_resources"],
                "environment": self.environment,
            }

            sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=subject[:100],
                Message=json.dumps(message, indent=2),
                MessageAttributes={
                    "severity": {
                        "DataType": "String",
                        "StringValue": finding["severity"],
                    },
                    "finding_type": {
                        "DataType": "String",
                        "StringValue": finding["finding_type"],
                    },
                },
            )
            logger.info(f"Sent SNS alert for finding {finding['event_id']}")
            return True

        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e}")
            return False


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for processing batched SQS messages.

    Writes Parquet per partition so partial failures only retry the affected
    messages. Returns a ReportBatchItemFailures response.
    """
    records = event.get("Records", [])
    logger.info(f"Processing {len(records)} SQS messages")

    processor = SecurityFindingProcessor()
    results: Dict[str, Any] = {
        "batchItemFailures": [],
        "processed_count": 0,
        "success_count": 0,
        "error_count": 0,
    }

    normalized_batch: List[Dict[str, Any]] = []
    event_id_to_msg_id: Dict[str, str] = {}

    for record in records:
        try:
            message_body = json.loads(record["body"])
            finding = json.loads(message_body) if isinstance(message_body, str) else message_body

            if not processor.validate_finding(finding):
                results["error_count"] += 1
                results["batchItemFailures"].append({"itemIdentifier": record["messageId"]})
                logger.error(f"Validation failed for message {record['messageId']}")
                continue

            normalized = processor.normalize_finding(finding)
            normalized_batch.append(normalized)
            event_id_to_msg_id[normalized["event_id"]] = record["messageId"]
            results["processed_count"] += 1

            processor.send_alert(normalized)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in SQS message {record['messageId']}: {e}")
            results["error_count"] += 1
            results["batchItemFailures"].append({"itemIdentifier": record["messageId"]})

        except Exception as e:
            logger.error(f"Unexpected error processing message {record['messageId']}: {e}")
            results["error_count"] += 1
            results["batchItemFailures"].append({"itemIdentifier": record["messageId"]})

    if normalized_batch:
        succeeded, failed = processor.store_findings_by_partition(normalized_batch)
        results["success_count"] = len(succeeded)
        results["error_count"] += len(failed)
        for event_id in failed:
            msg_id = event_id_to_msg_id.get(event_id)
            if msg_id:
                results["batchItemFailures"].append({"itemIdentifier": msg_id})

    logger.info(
        f"Processing complete: {results['success_count']} successful, "
        f"{results['error_count']} failed out of {len(records)} messages"
    )

    return results
