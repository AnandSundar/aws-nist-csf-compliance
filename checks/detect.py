"""NIST CSF 2.0 DETECT Function Checks.

This module implements security checks for the DETECT function which finds and
analyzes cybersecurity events and anomalies.

Checks implemented:
  DE-01: GuardDuty detector exists and status is ENABLED
  DE-02: AWS Security Hub is enabled
  DE-03: CloudTrail logging is active on primary trail
  DE-04: At least one CloudWatch alarm exists in the region
"""

import logging
from typing import Any

import botocore.exceptions
import boto3

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def run_checks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Run all DETECT function security checks.

    Args:
        session: boto3 Session object for making AWS API calls
        region: AWS region to scan

    Returns:
        List of check result dictionaries conforming to the check schema
    """
    results = []

    results.append(_check_guardduty(session, region))
    results.append(_check_security_hub(session))
    results.append(_check_cloudtrail_logging(session))
    results.append(_check_cloudwatch_alarms(session, region))

    return results


def _check_guardduty(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if GuardDuty detector exists and status is ENABLED.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "DE-01"
    control = "GuardDuty Enabled"
    aws_service = "guardduty"
    severity = "HIGH"

    try:
        guardduty_client = session.client("guardduty", region_name=region)
        detectors = guardduty_client.list_detectors()

        if "DetectorIds" in detectors and detectors["DetectorIds"]:
            for detector_id in detectors["DetectorIds"]:
                detector = guardduty_client.get_detector(DetectorId=detector_id)
                if detector.get("Status") == "ENABLED":
                    return {
                        "function": "DETECT",
                        "abbreviation": "DE",
                        "control_id": control_id,
                        "control": control,
                        "aws_service": aws_service,
                        "status": "PASS",
                        "detail": "GuardDuty is enabled in region",
                        "remediation": "",
                        "severity": severity,
                    }

        return {
            "function": "DETECT",
            "abbreviation": "DE",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "GuardDuty detector is not enabled in region",
            "remediation": "Enable GuardDuty in the current region",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        elif error_code == "InvalidInputException":
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "GuardDuty is not available in this region",
                "remediation": "Enable GuardDuty in the current region",
                "severity": severity,
            }
        else:
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_security_hub(session: boto3.Session) -> dict[str, Any]:
    """Check if AWS Security Hub is enabled.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "DE-02"
    control = "Security Hub Enabled"
    aws_service = "securityhub"
    severity = "HIGH"

    try:
        sh_client = session.client("securityhub")
        # DescribeHub returns info about Security Hub
        hub_info = sh_client.describe_hub()

        if "HubArn" in hub_info:
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": "AWS Security Hub is enabled",
                "remediation": "",
                "severity": severity,
            }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        elif error_code == "InvalidAccessException":
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "AWS Security Hub is not enabled",
                "remediation": "Enable AWS Security Hub for centralized security findings",
                "severity": severity,
            }
        else:
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }

    return {
        "function": "DETECT",
        "abbreviation": "DE",
        "control_id": control_id,
        "control": control,
        "aws_service": aws_service,
        "status": "FAIL",
        "detail": "AWS Security Hub is not enabled",
        "remediation": "Enable AWS Security Hub for centralized security findings",
        "severity": severity,
    }


def _check_cloudtrail_logging(session: boto3.Session) -> dict[str, Any]:
    """Check if CloudTrail logging is active on the primary trail.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "DE-03"
    control = "CloudTrail Logging Active"
    aws_service = "cloudtrail"
    severity = "HIGH"

    try:
        cloudtrail_client = session.client("cloudtrail")
        trails = cloudtrail_client.describe_trails()

        if "trailList" in trails and trails["trailList"]:
            for trail in trails["trailList"]:
                if trail.get("IsLogging"):
                    return {
                        "function": "DETECT",
                        "abbreviation": "DE",
                        "control_id": control_id,
                        "control": control,
                        "aws_service": aws_service,
                        "status": "PASS",
                        "detail": f"CloudTrail logging is active on trail: {trail.get('Name')}",
                        "remediation": "",
                        "severity": severity,
                    }

        return {
            "function": "DETECT",
            "abbreviation": "DE",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No CloudTrail with active logging found",
            "remediation": "Enable CloudTrail logging on at least one trail",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "DETECT",
                "abbreviation": "DE",
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
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_cloudwatch_alarms(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if at least one CloudWatch alarm exists in the region.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "DE-04"
    control = "CloudWatch Alarms Exist"
    aws_service = "cloudwatch"
    severity = "MEDIUM"

    try:
        cw_client = session.client("cloudwatch", region_name=region)
        alarms = cw_client.describe_alarms(MaxRecords=100)

        alarm_count = len(alarms.get("MetricAlarms", []))

        if alarm_count > 0:
            return {
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{alarm_count} CloudWatch alarm(s) exist in region",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "DETECT",
            "abbreviation": "DE",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No CloudWatch alarms exist in region",
            "remediation": "Create CloudWatch alarms to monitor critical metrics",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "DETECT",
                "abbreviation": "DE",
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
                "function": "DETECT",
                "abbreviation": "DE",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }
