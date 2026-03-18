#!/usr/bin/env python3
"""
Test Script for Security Data Lake

This script sends test security findings to the SQS queue to validate
the data lake pipeline functionality.
"""

import json
import sys
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List

import boto3
from botocore.exceptions import ClientError


class SecurityDataLakeTester:
    """Test class for the Security Data Lake system."""

    def __init__(self, queue_url: str, region: str = "us-east-1"):
        """
        Initialize the tester.

        Args:
            queue_url: SQS queue URL
            region: AWS region
        """
        self.queue_url = queue_url
        self.sqs_client = boto3.client("sqs", region_name=region)

    def generate_test_findings(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate test security findings.

        Args:
            count: Number of findings to generate

        Returns:
            List[Dict[str, Any]]: List of test findings
        """
        findings = []

        # Sample finding templates
        templates = [
            {
                "severity": "HIGH",
                "source": "aws-guardduty",
                "finding_type": "unauthorized-access",
                "description": "Suspicious activity detected on EC2 instance",
            },
            {
                "severity": "MEDIUM",
                "source": "aws-security-hub",
                "finding_type": "compliance-violation",
                "description": "S3 bucket has public read access enabled",
            },
            {
                "severity": "LOW",
                "source": "custom",
                "finding_type": "network-attack",
                "description": "Multiple failed login attempts detected",
            },
            {
                "severity": "CRITICAL",
                "source": "aws-guardduty",
                "finding_type": "malware",
                "description": "Malware detected on EC2 instance",
            },
            {
                "severity": "HIGH",
                "source": "aws-guardduty",
                "finding_type": "credential-compromise",
                "description": "Suspicious API calls using compromised credentials",
            },
        ]

        for i in range(count):
            template = templates[i % len(templates)]

            # Generate timestamp within last 24 hours
            timestamp = datetime.utcnow() - timedelta(hours=i)

            finding = {
                "event_id": f"test-finding-{uuid.uuid4().hex[:16]}",
                "timestamp": timestamp.isoformat() + "Z",
                "severity": template["severity"],
                "source": template["source"],
                "finding_type": template["finding_type"],
                "description": f"{template['description']} (Test #{i+1})",
                "affected_resources": [
                    f"arn:aws:ec2:us-east-1:123456789012:instance/i-test{i:06d}abcdef"
                ],
                "metadata": {
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "tags": {
                        "Environment": "test",
                        "Application": f"test-app-{i+1}",
                        "TestRun": datetime.utcnow().isoformat(),
                    },
                },
            }

            findings.append(finding)

        return findings

    def send_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Send a single finding to SQS.

        Args:
            finding: The security finding to send

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = self.sqs_client.send_message(
                QueueUrl=self.queue_url,
                MessageBody=json.dumps(finding),
                MessageAttributes={
                    "severity": {"DataType": "String", "StringValue": finding["severity"]},
                    "source": {"DataType": "String", "StringValue": finding["source"]},
                    "finding_type": {"DataType": "String", "StringValue": finding["finding_type"]},
                },
            )

            print(f"✓ Sent finding {finding['event_id']} (MessageId: {response['MessageId']})")
            return True

        except ClientError as e:
            print(f"✗ Failed to send finding {finding['event_id']}: {e}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error sending finding {finding['event_id']}: {e}")
            return False

    def send_test_findings(self, count: int = 5, delay: float = 1.0) -> Dict[str, Any]:
        """
        Send multiple test findings to SQS.

        Args:
            count: Number of findings to send
            delay: Delay between sends in seconds

        Returns:
            Dict[str, Any]: Test results
        """
        print(f"Sending {count} test findings to SQS queue...")
        print(f"Queue URL: {self.queue_url}")
        print("-" * 50)

        findings = self.generate_test_findings(count)
        results = {"total": count, "successful": 0, "failed": 0, "findings": []}

        for i, finding in enumerate(findings, 1):
            print(f"\nSending finding {i}/{count}:")
            print(f"  Event ID: {finding['event_id']}")
            print(f"  Severity: {finding['severity']}")
            print(f"  Source: {finding['source']}")
            print(f"  Type: {finding['finding_type']}")

            if self.send_finding(finding):
                results["successful"] += 1
                results["findings"].append({"event_id": finding["event_id"], "status": "sent"})
            else:
                results["failed"] += 1
                results["findings"].append({"event_id": finding["event_id"], "status": "failed"})

            # Add delay between sends
            if i < count:
                time.sleep(delay)

        print("\n" + "=" * 50)
        print("TEST RESULTS:")
        print(f"  Total findings: {results['total']}")
        print(f"  Successful: {results['successful']}")
        print(f"  Failed: {results['failed']}")
        print(f"  Success rate: {(results['successful']/results['total'])*100:.1f}%")

        return results

    def load_findings_from_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Load findings from a JSON file.

        Args:
            file_path: Path to the JSON file

        Returns:
            List[Dict[str, Any]]: List of findings
        """
        try:
            with open(file_path, "r") as f:
                findings = json.load(f)

            if not isinstance(findings, list):
                raise ValueError("JSON file must contain a list of findings")

            return findings

        except FileNotFoundError:
            print(f"✗ File not found: {file_path}")
            return []
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON in file {file_path}: {e}")
            return []
        except Exception as e:
            print(f"✗ Error loading file {file_path}: {e}")
            return []

    def send_findings_from_file(self, file_path: str, delay: float = 1.0) -> Dict[str, Any]:
        """
        Send findings from a JSON file.

        Args:
            file_path: Path to the JSON file
            delay: Delay between sends in seconds

        Returns:
            Dict[str, Any]: Test results
        """
        findings = self.load_findings_from_file(file_path)

        if not findings:
            return {"total": 0, "successful": 0, "failed": 0, "findings": []}

        print(f"Sending {len(findings)} findings from file: {file_path}")
        print(f"Queue URL: {self.queue_url}")
        print("-" * 50)

        results = {"total": len(findings), "successful": 0, "failed": 0, "findings": []}

        for i, finding in enumerate(findings, 1):
            print(f"\nSending finding {i}/{len(findings)}:")
            print(f"  Event ID: {finding.get('event_id', 'unknown')}")
            print(f"  Severity: {finding.get('severity', 'unknown')}")
            print(f"  Source: {finding.get('source', 'unknown')}")
            print(f"  Type: {finding.get('finding_type', 'unknown')}")

            if self.send_finding(finding):
                results["successful"] += 1
                results["findings"].append(
                    {"event_id": finding.get("event_id", "unknown"), "status": "sent"}
                )
            else:
                results["failed"] += 1
                results["findings"].append(
                    {"event_id": finding.get("event_id", "unknown"), "status": "failed"}
                )

            # Add delay between sends
            if i < len(findings):
                time.sleep(delay)

        print("\n" + "=" * 50)
        print("TEST RESULTS:")
        print(f"  Total findings: {results['total']}")
        print(f"  Successful: {results['successful']}")
        print(f"  Failed: {results['failed']}")
        if results["total"] > 0:
            print(f"  Success rate: {(results['successful']/results['total'])*100:.1f}%")

        return results


def main():
    """Main function to run the test script."""
    import argparse

    parser = argparse.ArgumentParser(description="Test Security Data Lake SQS Queue")
    parser.add_argument("--queue-url", required=True, help="SQS queue URL")
    parser.add_argument("--region", default="us-east-1", help="AWS region")
    parser.add_argument("--count", type=int, default=5, help="Number of test findings to send")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between sends in seconds")
    parser.add_argument("--file", help="JSON file containing findings to send")

    args = parser.parse_args()

    try:
        tester = SecurityDataLakeTester(args.queue_url, args.region)

        if args.file:
            results = tester.send_findings_from_file(args.file, args.delay)
        else:
            results = tester.send_test_findings(args.count, args.delay)

        # Exit with error code if any failures
        if results["failed"] > 0:
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
