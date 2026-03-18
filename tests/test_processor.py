"""Unit tests for the SecurityFindingProcessor Lambda function."""

import importlib
import json
from unittest.mock import patch, MagicMock

import boto3
import pytest
from moto import mock_aws

_processor_mod = importlib.import_module("src.lambda.processor")
SecurityFindingProcessor = _processor_mod.SecurityFindingProcessor
lambda_handler = _processor_mod.lambda_handler


class TestValidateFinding:
    def setup_method(self):
        self.processor = SecurityFindingProcessor()

    def test_valid_finding_passes(self, valid_finding):
        assert self.processor.validate_finding(valid_finding) is True

    def test_missing_required_field_fails(self, valid_finding):
        del valid_finding["severity"]
        assert self.processor.validate_finding(valid_finding) is False

    def test_invalid_severity_fails(self, valid_finding):
        valid_finding["severity"] = "ULTRA"
        assert self.processor.validate_finding(valid_finding) is False

    def test_invalid_timestamp_fails(self, valid_finding):
        valid_finding["timestamp"] = "not-a-date"
        assert self.processor.validate_finding(valid_finding) is False

    def test_unknown_source_warns_but_passes(self, valid_finding):
        valid_finding["source"] = "third-party-scanner"
        assert self.processor.validate_finding(valid_finding) is True

    def test_unknown_finding_type_warns_but_passes(self, valid_finding):
        valid_finding["finding_type"] = "novel-threat"
        assert self.processor.validate_finding(valid_finding) is True

    @pytest.mark.parametrize(
        "field", ["event_id", "timestamp", "severity", "source", "finding_type", "description"]
    )
    def test_each_required_field(self, valid_finding, field):
        del valid_finding[field]
        assert self.processor.validate_finding(valid_finding) is False


class TestNormalizeFinding:
    def setup_method(self):
        self.processor = SecurityFindingProcessor()

    def test_normalizes_severity_to_upper(self, valid_finding):
        valid_finding["severity"] = "high"
        result = self.processor.normalize_finding(valid_finding)
        assert result["severity"] == "HIGH"

    def test_normalizes_source_to_lower(self, valid_finding):
        valid_finding["source"] = "AWS-GuardDuty"
        result = self.processor.normalize_finding(valid_finding)
        assert result["source"] == "aws-guardduty"

    def test_adds_partition_columns(self, valid_finding):
        result = self.processor.normalize_finding(valid_finding)
        assert result["year"] == "2024"
        assert result["month"] == "06"
        assert result["day"] == "15"

    def test_flattens_metadata(self, valid_finding):
        result = self.processor.normalize_finding(valid_finding)
        assert result["metadata_account_id"] == "123456789012"
        assert result["metadata_region"] == "us-east-1"
        assert "metadata_tags" in result

    def test_defaults_missing_metadata(self, valid_finding):
        del valid_finding["metadata"]
        result = self.processor.normalize_finding(valid_finding)
        assert result["metadata_account_id"] == "unknown"
        assert result["metadata_region"] == "unknown"

    def test_defaults_missing_affected_resources(self, valid_finding):
        del valid_finding["affected_resources"]
        result = self.processor.normalize_finding(valid_finding)
        assert result["affected_resources"] == []

    def test_processed_at_is_utc_iso(self, valid_finding):
        result = self.processor.normalize_finding(valid_finding)
        assert "+00:00" in result["processed_at"] or "Z" in result["processed_at"]


class TestSendAlert:
    def setup_method(self):
        self.processor = SecurityFindingProcessor()

    @mock_aws
    def test_sends_alert_for_high_severity(self, valid_finding):
        sns = boto3.client("sns", region_name="us-east-1")
        topic = sns.create_topic(Name="test-alerts")
        self.processor.sns_topic_arn = topic["TopicArn"]

        normalized = self.processor.normalize_finding(valid_finding)
        assert self.processor.send_alert(normalized) is True

    @mock_aws
    def test_sends_alert_for_critical_severity(self, valid_finding):
        sns = boto3.client("sns", region_name="us-east-1")
        topic = sns.create_topic(Name="test-alerts")
        self.processor.sns_topic_arn = topic["TopicArn"]

        valid_finding["severity"] = "CRITICAL"
        normalized = self.processor.normalize_finding(valid_finding)
        assert self.processor.send_alert(normalized) is True

    def test_skips_alert_for_low_severity(self, low_severity_finding):
        normalized = self.processor.normalize_finding(low_severity_finding)
        assert self.processor.send_alert(normalized) is True

    def test_skips_alert_when_no_topic(self, valid_finding):
        self.processor.sns_topic_arn = ""
        normalized = self.processor.normalize_finding(valid_finding)
        assert self.processor.send_alert(normalized) is True


class TestStoreFindingsJsonFallback:
    def setup_method(self):
        self.processor = SecurityFindingProcessor()

    @mock_aws
    def test_json_fallback_writes_to_s3(self, valid_finding):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-security-data-lake")
        self.processor.s3_bucket = "test-security-data-lake"

        normalized = self.processor.normalize_finding(valid_finding)
        assert self.processor._store_findings_json_fallback([normalized]) is True

        key = (
            f"findings/year={normalized['year']}/month={normalized['month']}"
            f"/day={normalized['day']}/{normalized['event_id']}.json"
        )
        obj = s3.get_object(Bucket="test-security-data-lake", Key=key)
        body = json.loads(obj["Body"].read())
        assert body["event_id"] == "test-finding-001"


class TestStoreByPartition:
    def setup_method(self):
        self.processor = SecurityFindingProcessor()

    def test_groups_by_partition_and_returns_success(self, valid_finding, low_severity_finding):
        n1 = self.processor.normalize_finding(valid_finding)
        n2 = self.processor.normalize_finding(low_severity_finding)

        with patch.object(self.processor, "_write_partition", return_value=True):
            succeeded, failed = self.processor.store_findings_by_partition([n1, n2])

        assert n1["event_id"] in succeeded
        assert n2["event_id"] in succeeded
        assert len(failed) == 0

    def test_partition_failure_falls_back_to_json(self, valid_finding):
        normalized = self.processor.normalize_finding(valid_finding)

        with (
            patch.object(self.processor, "_write_partition", return_value=False),
            patch.object(self.processor, "_store_findings_json_fallback", return_value=True) as fb,
        ):
            succeeded, failed = self.processor.store_findings_by_partition([normalized])

        fb.assert_called_once()
        assert normalized["event_id"] in succeeded
        assert len(failed) == 0

    def test_total_failure_returns_failed_ids(self, valid_finding):
        normalized = self.processor.normalize_finding(valid_finding)

        with (
            patch.object(self.processor, "_write_partition", return_value=False),
            patch.object(self.processor, "_store_findings_json_fallback", return_value=False),
        ):
            succeeded, failed = self.processor.store_findings_by_partition([normalized])

        assert len(succeeded) == 0
        assert normalized["event_id"] in failed

    def test_mixed_partition_results(self, valid_finding, low_severity_finding):
        """One partition succeeds, another fails entirely."""
        n1 = self.processor.normalize_finding(valid_finding)
        low_severity_finding["timestamp"] = "2025-01-10T08:00:00Z"
        n2 = self.processor.normalize_finding(low_severity_finding)

        call_count = 0

        def write_side_effect(findings):
            nonlocal call_count
            call_count += 1
            return call_count == 1

        with (
            patch.object(self.processor, "_write_partition", side_effect=write_side_effect),
            patch.object(self.processor, "_store_findings_json_fallback", return_value=False),
        ):
            succeeded, failed = self.processor.store_findings_by_partition([n1, n2])

        assert len(succeeded) + len(failed) == 2
        assert len(failed) >= 1


class TestLambdaHandler:
    @mock_aws
    def test_handler_processes_valid_batch(self, sqs_event):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-security-data-lake")
        sns = boto3.client("sns", region_name="us-east-1")
        sns.create_topic(Name="test-alerts")

        with patch.object(
            SecurityFindingProcessor,
            "store_findings_by_partition",
            return_value=({"test-finding-001"}, set()),
        ):
            result = lambda_handler(sqs_event, None)

        assert result["success_count"] == 1
        assert result["error_count"] == 0
        assert len(result["batchItemFailures"]) == 0

    def test_handler_rejects_invalid_json(self):
        event = {
            "Records": [
                {
                    "messageId": "msg-bad",
                    "body": "not-valid-json{{{",
                    "receiptHandle": "r",
                    "attributes": {},
                    "messageAttributes": {},
                    "md5OfBody": "",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:q",
                    "awsRegion": "us-east-1",
                }
            ]
        }
        result = lambda_handler(event, None)
        assert result["error_count"] == 1
        assert len(result["batchItemFailures"]) == 1

    @mock_aws
    def test_handler_partial_batch_failure(self, sqs_batch_event):
        """First message succeeds, second fails — only second is reported."""
        with patch.object(
            SecurityFindingProcessor,
            "store_findings_by_partition",
            return_value=({"test-finding-001"}, {"test-finding-low"}),
        ):
            result = lambda_handler(sqs_batch_event, None)

        assert result["success_count"] == 1
        assert result["error_count"] == 1
        assert len(result["batchItemFailures"]) == 1

    @mock_aws
    def test_handler_total_store_failure(self, sqs_batch_event):
        """All writes fail — all messages reported as failures."""
        with patch.object(
            SecurityFindingProcessor,
            "store_findings_by_partition",
            return_value=(set(), {"test-finding-001", "test-finding-low"}),
        ):
            result = lambda_handler(sqs_batch_event, None)

        assert result["error_count"] == 2
        assert len(result["batchItemFailures"]) == 2

    def test_handler_empty_records(self):
        result = lambda_handler({"Records": []}, None)
        assert result["processed_count"] == 0
        assert result["success_count"] == 0
