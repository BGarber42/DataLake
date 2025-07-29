"""
Security Data Lake Lambda Processor

This Lambda function processes security findings from SQS, normalizes the data,
and stores it in S3 with date-based partitioning for efficient Athena queries.
"""

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

# Environment variables
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'dev')

# Constants
SEVERITY_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
SOURCE_TYPES = ['aws-guardduty', 'aws-security-hub', 'aws-config', 'custom']
FINDING_TYPES = [
    'malware', 'unauthorized-access', 'data-exfiltration', 'privilege-escalation',
    'network-attack', 'credential-compromise', 'compliance-violation', 'other'
]


class SecurityFindingProcessor:
    """Processes and normalizes security findings."""
    
    def __init__(self):
        self.s3_bucket = S3_BUCKET_NAME
        self.sns_topic_arn = SNS_TOPIC_ARN
        self.environment = ENVIRONMENT
    
    def validate_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Validate the security finding schema.
        
        Args:
            finding: The security finding dictionary
            
        Returns:
            bool: True if valid, False otherwise
        """
        required_fields = ['event_id', 'timestamp', 'severity', 'source', 'finding_type', 'description']
        
        # Check required fields
        for field in required_fields:
            if field not in finding:
                logger.error(f"Missing required field: {field}")
                return False
        
        # Validate severity
        if finding['severity'] not in SEVERITY_LEVELS:
            logger.error(f"Invalid severity level: {finding['severity']}")
            return False
        
        # Validate source
        if finding['source'] not in SOURCE_TYPES:
            logger.warning(f"Unknown source type: {finding['source']}")
        
        # Validate finding type
        if finding['finding_type'] not in FINDING_TYPES:
            logger.warning(f"Unknown finding type: {finding['finding_type']}")
        
        # Validate timestamp format
        try:
            datetime.fromisoformat(finding['timestamp'].replace('Z', '+00:00'))
        except ValueError:
            logger.error(f"Invalid timestamp format: {finding['timestamp']}")
            return False
        
        return True
    
    def normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize the security finding data.
        
        Args:
            finding: The raw security finding
            
        Returns:
            Dict[str, Any]: Normalized finding
        """
        # Parse timestamp
        timestamp = datetime.fromisoformat(finding['timestamp'].replace('Z', '+00:00'))
        
        # Create normalized finding
        normalized = {
            'event_id': finding['event_id'],
            'timestamp': finding['timestamp'],
            'severity': finding['severity'].upper(),
            'source': finding['source'].lower(),
            'finding_type': finding['finding_type'].lower(),
            'description': finding['description'],
            'affected_resources': finding.get('affected_resources', []),
            'metadata': finding.get('metadata', {}),
            'processed_at': datetime.utcnow().isoformat() + 'Z',
            'partition_year': str(timestamp.year),
            'partition_month': f"{timestamp.month:02d}",
            'partition_day': f"{timestamp.day:02d}"
        }
        
        # Add default metadata if not present
        if 'account_id' not in normalized['metadata']:
            normalized['metadata']['account_id'] = 'unknown'
        if 'region' not in normalized['metadata']:
            normalized['metadata']['region'] = 'unknown'
        if 'tags' not in normalized['metadata']:
            normalized['metadata']['tags'] = {}
        
        return normalized
    
    def store_finding(self, finding: Dict[str, Any]) -> bool:
        """
        Store the normalized finding in S3.
        
        Args:
            finding: The normalized security finding
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create S3 key with partitioning
            year = finding['partition_year']
            month = finding['partition_month']
            day = finding['partition_day']
            event_id = finding['event_id']
            
            s3_key = f"findings/year={year}/month={month}/day={day}/{event_id}.json"
            
            # Upload to S3
            s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=json.dumps(finding, indent=2),
                ContentType='application/json',
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Successfully stored finding {event_id} in S3: {s3_key}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to store finding in S3: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error storing finding: {e}")
            return False
    
    def send_alert(self, finding: Dict[str, Any]) -> bool:
        """
        Send SNS alert for high-severity findings.
        
        Args:
            finding: The security finding
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.sns_topic_arn or finding['severity'] not in ['HIGH', 'CRITICAL']:
            return True
        
        try:
            # Create alert message
            alert_message = {
                'subject': f"Security Alert: {finding['severity']} {finding['finding_type']}",
                'message': {
                    'event_id': finding['event_id'],
                    'severity': finding['severity'],
                    'source': finding['source'],
                    'finding_type': finding['finding_type'],
                    'description': finding['description'],
                    'timestamp': finding['timestamp'],
                    'affected_resources': finding['affected_resources'],
                    'environment': self.environment
                }
            }
            
            # Send SNS message
            sns_client.publish(
                TopicArn=self.sns_topic_arn,
                Subject=alert_message['subject'],
                Message=json.dumps(alert_message['message'], indent=2),
                MessageAttributes={
                    'severity': {
                        'DataType': 'String',
                        'StringValue': finding['severity']
                    },
                    'finding_type': {
                        'DataType': 'String',
                        'StringValue': finding['finding_type']
                    }
                }
            )
            
            logger.info(f"Sent SNS alert for finding {finding['event_id']}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to send SNS alert: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending SNS alert: {e}")
            return False
    
    def process_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single security finding.
        
        Args:
            finding: The raw security finding
            
        Returns:
            Dict[str, Any]: Processing result
        """
        result = {
            'success': False,
            'event_id': finding.get('event_id', 'unknown'),
            'errors': []
        }
        
        try:
            # Validate finding
            if not self.validate_finding(finding):
                result['errors'].append('Validation failed')
                return result
            
            # Normalize finding
            normalized_finding = self.normalize_finding(finding)
            
            # Store in S3
            if not self.store_finding(normalized_finding):
                result['errors'].append('Failed to store in S3')
                return result
            
            # Send alert if high severity
            if not self.send_alert(normalized_finding):
                result['errors'].append('Failed to send SNS alert')
                # Don't fail the entire process for alert failures
            
            result['success'] = True
            logger.info(f"Successfully processed finding {result['event_id']}")
            
        except Exception as e:
            logger.error(f"Error processing finding {result['event_id']}: {e}")
            result['errors'].append(str(e))
        
        return result


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda function handler for processing SQS messages.
    
    Args:
        event: SQS event containing security findings
        context: Lambda context
        
    Returns:
        Dict[str, Any]: Processing results
    """
    logger.info(f"Processing {len(event.get('Records', []))} SQS messages")
    
    processor = SecurityFindingProcessor()
    results = {
        'batchItemFailures': [],
        'processed_count': 0,
        'success_count': 0,
        'error_count': 0
    }
    
    for record in event.get('Records', []):
        try:
            # Parse SQS message
            message_body = json.loads(record['body'])
            finding = json.loads(message_body) if isinstance(message_body, str) else message_body
            
            # Process finding
            result = processor.process_finding(finding)
            
            results['processed_count'] += 1
            
            if result['success']:
                results['success_count'] += 1
            else:
                results['error_count'] += 1
                # Add to batch failures for SQS retry
                results['batchItemFailures'].append({
                    'itemIdentifier': record['messageId']
                })
                logger.error(f"Failed to process finding {result['event_id']}: {result['errors']}")
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in SQS message: {e}")
            results['error_count'] += 1
            results['batchItemFailures'].append({
                'itemIdentifier': record['messageId']
            })
        
        except Exception as e:
            logger.error(f"Unexpected error processing SQS message: {e}")
            results['error_count'] += 1
            results['batchItemFailures'].append({
                'itemIdentifier': record['messageId']
            })
    
    logger.info(f"Processing complete: {results['success_count']} successful, {results['error_count']} failed")
    
    return results 