import os
import pytest

os.environ['S3_BUCKET_NAME'] = 'test-security-data-lake'
os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-alerts'
os.environ['ENVIRONMENT'] = 'test'
os.environ['LOG_LEVEL'] = 'DEBUG'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
os.environ['AWS_SECURITY_TOKEN'] = 'testing'
os.environ['AWS_SESSION_TOKEN'] = 'testing'


@pytest.fixture
def valid_finding():
    return {
        'event_id': 'test-finding-001',
        'timestamp': '2024-06-15T10:30:00Z',
        'severity': 'HIGH',
        'source': 'aws-guardduty',
        'finding_type': 'unauthorized-access',
        'description': 'Suspicious activity detected on EC2 instance',
        'affected_resources': [
            'arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890'
        ],
        'metadata': {
            'account_id': '123456789012',
            'region': 'us-east-1',
            'tags': {'Environment': 'production'},
        },
    }


@pytest.fixture
def low_severity_finding(valid_finding):
    return {**valid_finding, 'event_id': 'test-finding-low', 'severity': 'LOW'}


@pytest.fixture
def sqs_event(valid_finding):
    import json

    return {
        'Records': [
            {
                'messageId': 'msg-001',
                'body': json.dumps(valid_finding),
                'receiptHandle': 'test-receipt',
                'attributes': {},
                'messageAttributes': {},
                'md5OfBody': '',
                'eventSource': 'aws:sqs',
                'eventSourceARN': 'arn:aws:sqs:us-east-1:123456789012:test-queue',
                'awsRegion': 'us-east-1',
            }
        ]
    }


@pytest.fixture
def sqs_batch_event(valid_finding, low_severity_finding):
    import json

    findings = [valid_finding, low_severity_finding]
    return {
        'Records': [
            {
                'messageId': f'msg-{i:03d}',
                'body': json.dumps(f),
                'receiptHandle': f'receipt-{i}',
                'attributes': {},
                'messageAttributes': {},
                'md5OfBody': '',
                'eventSource': 'aws:sqs',
                'eventSourceARN': 'arn:aws:sqs:us-east-1:123456789012:test-queue',
                'awsRegion': 'us-east-1',
            }
            for i, f in enumerate(findings)
        ]
    }
