"""NIST CSF 2.0 RESPOND Function Checks.

This module implements security checks for the RESPOND function which takes action
on detected cybersecurity incidents.

Checks implemented:
  RS-01: At least one EventBridge rule exists
  RS-02: At least one SNS topic exists
  RS-03: At least one Lambda function exists
"""

import logging
from typing import Any

import botocore.exceptions
import boto3

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def run_checks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Run all RESPOND function security checks.

    Args:
        session: boto3 Session object for making AWS API calls
        region: AWS region to scan

    Returns:
        List of check result dictionaries conforming to the check schema
    """
    results = []

    results.append(_check_eventbridge_rules(session, region))
    results.append(_check_sns_topics(session, region))
    results.append(_check_lambda_functions(session, region))

    return results


def _check_eventbridge_rules(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if at least one EventBridge rule exists.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "RS-01"
    control = "EventBridge Rules Exist"
    aws_service = "events"
    severity = "MEDIUM"

    try:
        events_client = session.client("events", region_name=region)
        rules = events_client.list_rules(MaxResults=100)

        if "Rules" in rules and rules["Rules"]:
            return {
                "function": "RESPOND",
                "abbreviation": "RS",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{len(rules['Rules'])} EventBridge rule(s) exist in region",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "RESPOND",
            "abbreviation": "RS",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No EventBridge rules exist in region",
            "remediation": "Create EventBridge rules for automated incident response",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "RESPOND",
                "abbreviation": "RS",
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
                "function": "RESPOND",
                "abbreviation": "RS",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_sns_topics(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if at least one SNS topic exists.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "RS-02"
    control = "SNS Topics Exist"
    aws_service = "sns"
    severity = "MEDIUM"

    try:
        sns_client = session.client("sns", region_name=region)
        topics = sns_client.list_topics()

        if "Topics" in topics and topics["Topics"]:
            return {
                "function": "RESPOND",
                "abbreviation": "RS",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{len(topics['Topics'])} SNS topic(s) exist for alerting",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "RESPOND",
            "abbreviation": "RS",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No SNS topics exist for alerting",
            "remediation": "Create SNS topics for security alert notifications",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "RESPOND",
                "abbreviation": "RS",
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
                "function": "RESPOND",
                "abbreviation": "RS",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_lambda_functions(session: boto3.Session, region: str) -> dict[str, Any]:
    """Check if at least one Lambda function exists.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "RS-03"
    control = "Lambda Functions Exist"
    aws_service = "lambda"
    severity = "LOW"

    try:
        lambda_client = session.client("lambda", region_name=region)
        functions = lambda_client.list_functions(MaxItems=100)

        if "Functions" in functions and functions["Functions"]:
            return {
                "function": "RESPOND",
                "abbreviation": "RS",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{len(functions['Functions'])} Lambda function(s) exist for automation",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "RESPOND",
            "abbreviation": "RS",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No Lambda functions exist for automated response",
            "remediation": "Create Lambda functions for automated security response",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "RESPOND",
                "abbreviation": "RS",
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
                "function": "RESPOND",
                "abbreviation": "RS",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }
