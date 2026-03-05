"""NIST CSF 2.0 IDENTIFY Function Checks.

This module implements security checks for the IDENTIFY function which understands
assets, risks, and vulnerabilities across the environment.

Checks implemented:
  ID-01: AWS Config recorder is enabled in current region
  ID-02: IAM Access Analyzer has at least one ACTIVE analyzer
  ID-03: CloudTrail has multi-region trail with logging enabled
  ID-04: AWS Config delivery channel is configured
"""

import logging
from typing import Any

import botocore.exceptions
import boto3

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def run_checks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Run all IDENTIFY function security checks.

    Args:
        session: boto3 Session object for making AWS API calls
        region: AWS region to scan

    Returns:
        List of check result dictionaries conforming to the check schema
    """
    results = []

    results.append(_check_config_recorder(session, region))
    results.append(_check_access_analyzer(session))
    results.append(_check_cloudtrail_multiregion(session))
    results.append(_check_config_delivery_channel(session, region))

    return results


def _check_config_recorder(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if AWS Config recorder is enabled in the current region.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "ID-01"
    control = "AWS Config Recorder Enabled"
    aws_service = "config"
    severity = "HIGH"

    try:
        config_client = session.client("config", region_name=region)
        recorders = config_client.describe_configuration_recorders()

        if (
            "ConfigurationRecorders" in recorders
            and recorders["ConfigurationRecorders"]
        ):
            for recorder in recorders["ConfigurationRecorders"]:
                if recorder.get("recordingGroup", {}).get("allSupported", False):
                    return {
                        "function": "IDENTIFY",
                        "abbreviation": "ID",
                        "control_id": control_id,
                        "control": control,
                        "aws_service": aws_service,
                        "status": "PASS",
                        "detail": "AWS Config recorder is enabled with all resources in region",
                        "remediation": "",
                        "severity": severity,
                    }

        return {
            "function": "IDENTIFY",
            "abbreviation": "ID",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "AWS Config recorder is not enabled or not recording all resources",
            "remediation": "Enable AWS Config recorder with allSupported=True in current region",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "IDENTIFY",
                "abbreviation": "ID",
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
                "function": "IDENTIFY",
                "abbreviation": "ID",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_access_analyzer(session: boto3.Session) -> dict[str, Any]:
    """Check if IAM Access Analyzer has at least one ACTIVE analyzer.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "ID-02"
    control = "IAM Access Analyzer Active"
    aws_service = "accessanalyzer"
    severity = "HIGH"

    try:
        analyzer_client = session.client("accessanalyzer")
        analyzers = analyzer_client.list_analyzers()

        if "analyzers" in analyzers and analyzers["analyzers"]:
            active_analyzers = [
                a for a in analyzers["analyzers"] if a.get("status") == "ACTIVE"
            ]
            if active_analyzers:
                return {
                    "function": "IDENTIFY",
                    "abbreviation": "ID",
                    "control_id": control_id,
                    "control": control,
                    "aws_service": aws_service,
                    "status": "PASS",
                    "detail": f"IAM Access Analyzer has {len(active_analyzers)} active analyzer(s)",
                    "remediation": "",
                    "severity": severity,
                }

        return {
            "function": "IDENTIFY",
            "abbreviation": "ID",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No active IAM Access Analyzer found",
            "remediation": "Create an IAM Access Analyzer to identify resource access risks",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "IDENTIFY",
                "abbreviation": "ID",
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
                "function": "IDENTIFY",
                "abbreviation": "ID",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "IAM Access Analyzer is not available in this region",
                "remediation": "Enable IAM Access Analyzer in the account",
                "severity": severity,
            }
        else:
            return {
                "function": "IDENTIFY",
                "abbreviation": "ID",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_cloudtrail_multiregion(session: boto3.Session) -> dict[str, Any]:
    """Check if CloudTrail has multi-region trail with logging enabled.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "ID-03"
    control = "CloudTrail Multi-Region Enabled"
    aws_service = "cloudtrail"
    severity = "HIGH"

    try:
        cloudtrail_client = session.client("cloudtrail")
        trails = cloudtrail_client.describe_trails()

        if "trailList" in trails and trails["trailList"]:
            for trail in trails["trailList"]:
                if trail.get("IsMultiRegionTrail") and trail.get("IsLogging"):
                    return {
                        "function": "IDENTIFY",
                        "abbreviation": "ID",
                        "control_id": control_id,
                        "control": control,
                        "aws_service": aws_service,
                        "status": "PASS",
                        "detail": f"CloudTrail multi-region logging is enabled on trail: {trail.get('Name')}",
                        "remediation": "",
                        "severity": severity,
                    }

        return {
            "function": "IDENTIFY",
            "abbreviation": "ID",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No multi-region CloudTrail with logging enabled found",
            "remediation": "Create a multi-region CloudTrail with logging enabled",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "IDENTIFY",
                "abbreviation": "ID",
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
                "function": "IDENTIFY",
                "abbreviation": "ID",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_config_delivery_channel(
    session: boto3.Session, region: str
) -> dict[str, Any]:
    """Check if AWS Config delivery channel is configured.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "ID-04"
    control = "AWS Config Delivery Channel Configured"
    aws_service = "config"
    severity = "MEDIUM"

    try:
        config_client = session.client("config", region_name=region)
        channel = config_client.describe_delivery_channels()

        if "DeliveryChannels" in channel and channel["DeliveryChannels"]:
            return {
                "function": "IDENTIFY",
                "abbreviation": "ID",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": "AWS Config delivery channel is configured",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "IDENTIFY",
            "abbreviation": "ID",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "AWS Config delivery channel is not configured",
            "remediation": "Configure AWS Config delivery channel to deliver configuration snapshots",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "IDENTIFY",
                "abbreviation": "ID",
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
                "function": "IDENTIFY",
                "abbreviation": "ID",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }
