import json
import boto3
import logging
import hashlib
import time
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ssm = boto3.client('ssm')
incidents = boto3.client('ssm-incidents')

# Your SSM Automation Document name for remediation
SSM_AUTOMATION_DOC = "RemediatePublicS3Bucket"

# Your Incident Manager Response Plan ARN
INCIDENT_RESPONSE_PLAN_ARN = "arn:aws:ssm-incidents::85xxxxxxxxxxx:response-plan/S3Bucket_Security_IncidentResponse"

def generate_client_token(bucket_name, event_time):
    """
    Generate a client token using bucket name and 3-minute window to prevent duplicate incidents.
    Parses timestamps with or without milliseconds.
    """
    try:
        dt = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        dt = datetime.strptime(event_time, "%Y-%m-%dT%H:%M:%SZ")

    bucket_minute = dt.minute - (dt.minute % 15)
    rounded_time = dt.replace(minute=bucket_minute, second=0, microsecond=0)
    raw_string = f"{bucket_name}-{rounded_time.strftime('%Y%m%dT%H%M')}"
    return hashlib.sha256(raw_string.encode()).hexdigest()

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Extract the S3 bucket info from Security Hub finding
        findings = event.get('detail', {}).get('findings', [])
        if not findings:
            logger.warning("No findings in event")
            return

        for finding in findings:
            resources = finding.get('Resources', [])
            if not resources:
                logger.warning("No resources in finding")
                continue

            for resource in resources:
                if resource.get('Type') == 'AwsS3Bucket':
                    bucket_arn = resource.get('Id')
                    bucket_name = bucket_arn.split(':::')[-1]
                    event_time = finding.get('UpdatedAt')

                    logger.info(f"Processing bucket: {bucket_name} at {event_time}")

                    # Start SSM Automation runbook (remediation)
                    ssm_response = ssm.start_automation_execution(
                        DocumentName=SSM_AUTOMATION_DOC,
                        Parameters={
                            'BucketName': [bucket_name]
                        }
                    )
                    logger.info(f"Started SSM Automation execution: {ssm_response['AutomationExecutionId']}")

                    # Start Incident Manager incident with clientToken for deduplication
                    client_token = generate_client_token(bucket_name, event_time)

                    start = time.time()
                    incident_response = incidents.start_incident(
                        responsePlanArn=INCIDENT_RESPONSE_PLAN_ARN,
                        title=f"Public S3 Bucket Exposure - {bucket_name}",
                        impact=3,
                        clientToken=client_token,
                        relatedItems=[
                            {
                                "identifier": {
                                    "type": "INVOLVED_RESOURCE",
                                    "value": {
                                        "arn": bucket_arn
                                    }
                                },
                                "title": f"S3 Bucket Finding - {bucket_name}"
                            }
                        ]
                    )
                    end = time.time()
                    logger.info(f"🕒 Incident creation took: {end - start:.2f} seconds")
                    
                    # Added debug log for incident response
                    logger.info(f"Incident Manager response: {json.dumps(incident_response, default=str)}")

                    logger.info(f"Started incident: {incident_response['incidentRecordArn']}")

    except Exception as e:
        logger.error(f"Error processing event: {e}")
        raise e
