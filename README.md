# AWS Automated Incident Response for Public S3 Buckets

![Workflow Diagram](https://github.com/user-attachments/assets/d6d2351e-293f-4890-a2a0-5f58eb9f4112)

Automated remediation workflow for public S3 buckets.

## Features

- **Detection**: Handled by AWS Security Hub.
- **Remediation**: Automatically Immediate action for S3 buckets
- **Comprehensive tracking**: Full incident lifecycle management in Systems Manager.
- **Alerting**: E-mail Configured for notifications 
- **Audit trail**: Detailed logging of all remediation actions

## Architecture Overview

### Core Workflow
1. **Detection**  
   - Triggers via:
     - AWS Security Hub.
2. **Remediation**  
   - SSM Automation Runbook executes:
     - Bucket ACL lockdown
     - Bucket policy remediation
     - BlockPublicAccess on S3 Public Buckets
3. **Incident Management**  
   - Systems Manager Incident Manager
4. **Notification**  
   - Email alerts via the Systems Manager feature Incident Manager

## Key Components

| Component | Description | AWS Service |
|-----------|-------------|-------------|
| **Detection Layer** | Identifies public S3 buckets | AWS Security Hub |
| **Orchestrator** | Coordinates remediation workflow | AWS Lambda |
| **Remediation** | Executes security fixes | AWS SSM Automation(Runbook).ie Document |
| **Incident Tracker** | Manages incident lifecycle | Incident Manager |
