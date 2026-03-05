"""NIST CSF 2.0 RECOVER Function Checks.

This module implements security checks for the RECOVER function which restores
capabilities impaired by cybersecurity incidents.

Checks implemented:
  RC-01: At least one AWS Backup plan exists
  RC-02: At least one CloudFormation stack exists in the region
  RC-03: At least one S3 bucket has versioning enabled (data recovery baseline)
"""

import logging
from typing import Any

import botocore.exceptions
import boto3

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def run_checks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Run all RECOVER function security checks.

    Args:
        session: boto3 Session object for making AWS API calls
        region: AWS region to scan

    Returns:
        List of check result dictionaries conforming to the check schema
    """
    results = []

    results.append(_check_backup_plans(session))
    results.append(_check_cloudformation_stacks(session, region))
    results.append(_check_s3_versioning(session))

    return results


def _check_backup_plans(session: boto3.Session) -> dict[str, Any]:
    """Check if at least one AWS Backup plan exists.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "RC-01"
    control = "AWS Backup Plans Exist"
    aws_service = "backup"
    severity = "HIGH"

    try:
        backup_client = session.client("backup")
        plans = backup_client.list_backup_plans()

        if "BackupPlansList" in plans and plans["BackupPlansList"]:
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{len(plans['BackupPlansList'])} AWS Backup plan(s) exist",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "RECOVER",
            "abbreviation": "RC",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No AWS Backup plans exist",
            "remediation": "Create AWS Backup plans for automated data recovery",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        elif error_code == "InvalidRequestException":
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "AWS Backup is not available in this region",
                "remediation": "Enable AWS Backup in the account",
                "severity": severity,
            }
        else:
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_cloudformation_stacks(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if at least one CloudFormation stack exists in the region.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "RC-02"
    control = "CloudFormation Stacks Exist"
    aws_service = "cloudformation"
    severity = "MEDIUM"

    try:
        cf_client = session.client("cloudformation", region_name=region)
        stacks = cf_client.list_stacks(
            StackStatusFilter=[
                "CREATE_COMPLETE",
                "UPDATE_COMPLETE",
                "UPDATE_ROLLBACK_COMPLETE",
            ]
        )

        if "StackSummaries" in stacks and stacks["StackSummaries"]:
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{len(stacks['StackSummaries'])} CloudFormation stack(s) exist for IaC recovery",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "RECOVER",
            "abbreviation": "RC",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No CloudFormation stacks exist for IaC recovery",
            "remediation": "Use CloudFormation for infrastructure as code to enable recovery",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        else:
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_s3_versioning(session: boto3.Session) -> dict[str, Any]:
    """Check if at least one S3 bucket has versioning enabled.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "RC-03"
    control = "S3 Bucket Versioning Enabled"
    aws_service = "s3"
    severity = "HIGH"

    try:
        s3_client = session.client("s3")
        buckets = s3_client.list_buckets()

        if "Buckets" in buckets and buckets["Buckets"]:
            for bucket in buckets["Buckets"]:
                bucket_name = bucket["Name"]
                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get("Status")
                    if status == "Enabled":
                        return {
                            "function": "RECOVER",
                            "abbreviation": "RC",
                            "control_id": control_id,
                            "control": control,
                            "aws_service": aws_service,
                            "status": "PASS",
                            "detail": f"S3 bucket '{bucket_name}' has versioning enabled for data recovery",
                            "remediation": "",
                            "severity": severity,
                        }
                except botocore.exceptions.ClientError:
                    pass

        return {
            "function": "RECOVER",
            "abbreviation": "RC",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No S3 buckets have versioning enabled for data recovery",
            "remediation": "Enable S3 bucket versioning for data protection and recovery",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        else:
            return {
                "function": "RECOVER",
                "abbreviation": "RC",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }
