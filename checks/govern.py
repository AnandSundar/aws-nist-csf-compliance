"""NIST CSF 2.0 GOVERN Function Checks.

This module implements security checks for the GOVERN function which establishes
cybersecurity risk management strategy, expectations, and policy.

Checks implemented:
  GV-01: IAM account password policy exists with min 14-char length
  GV-02: Root account MFA is enabled
  GV-03: AWS Organizations is configured
  GV-04: Root account has no active access keys
"""

import logging
from typing import Any

import botocore.exceptions
import boto3

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def run_checks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Run all GOVERN function security checks.

    Args:
        session: boto3 Session object for making AWS API calls
        region: AWS region to scan

    Returns:
        List of check result dictionaries conforming to the check schema
    """
    results = []

    results.append(_check_password_policy(session))
    results.append(_check_root_mfa(session))
    results.append(_check_organizations(session))
    results.append(_check_root_access_keys(session))

    return results


def _check_password_policy(session: boto3.Session) -> dict[str, Any]:
    """Check if IAM password policy requires minimum 14-character length.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "GV-01"
    control = "IAM Password Policy - Minimum 14 Characters"
    aws_service = "iam"
    severity = "HIGH"

    try:
        iam_client = session.client("iam")
        policy = iam_client.get_account_password_policy()

        if "PasswordPolicy" in policy:
            min_length = policy["PasswordPolicy"].get("MinimumPasswordLength", 0)
            if min_length >= 14:
                return {
                    "function": "GOVERN",
                    "abbreviation": "GV",
                    "control_id": control_id,
                    "control": control,
                    "aws_service": aws_service,
                    "status": "PASS",
                    "detail": f"Password policy requires {min_length}-character minimum",
                    "remediation": "",
                    "severity": severity,
                }
            else:
                return {
                    "function": "GOVERN",
                    "abbreviation": "GV",
                    "control_id": control_id,
                    "control": control,
                    "aws_service": aws_service,
                    "status": "FAIL",
                    "detail": f"Password policy only requires {min_length} characters",
                    "remediation": "Update password policy to require minimum 14 characters",
                    "severity": severity,
                }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
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
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }

    return {
        "function": "GOVERN",
        "abbreviation": "GV",
        "control_id": control_id,
        "control": control,
        "aws_service": aws_service,
        "status": "FAIL",
        "detail": "No account password policy configured",
        "remediation": "Create an IAM account password policy with minimum 14 characters",
        "severity": severity,
    }


def _check_root_mfa(session: boto3.Session) -> dict[str, Any]:
    """Check if root account has MFA enabled.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "GV-02"
    control = "Root Account MFA Enabled"
    aws_service = "iam"
    severity = "HIGH"

    try:
        iam_client = session.client("iam")
        summary = iam_client.get_account_summary()

        mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
        if mfa_enabled == 1:
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": "Root account has MFA enabled",
                "remediation": "",
                "severity": severity,
            }
        else:
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "Root account does not have MFA enabled",
                "remediation": "Enable MFA on the root account using AWS Console or CLI",
                "severity": severity,
            }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
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
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_organizations(session: boto3.Session) -> dict[str, Any]:
    """Check if AWS Organizations is configured.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "GV-03"
    control = "AWS Organizations Configured"
    aws_service = "organizations"
    severity = "MEDIUM"

    try:
        org_client = session.client("organizations")
        org = org_client.describe_organization()

        if "Organization" in org:
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"AWS Organizations is configured with ID: {org['Organization']['Id']}",
                "remediation": "",
                "severity": severity,
            }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        elif error_code == "AWSOrganizationsNotInUseException":
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "AWS Organizations is not configured for this account",
                "remediation": "Create or join an AWS Organization for centralized governance",
                "severity": severity,
            }
        else:
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }

    return {
        "function": "GOVERN",
        "abbreviation": "GV",
        "control_id": control_id,
        "control": control,
        "aws_service": aws_service,
        "status": "FAIL",
        "detail": "AWS Organizations is not configured",
        "remediation": "Create or join an AWS Organization for centralized governance",
        "severity": severity,
    }


def _check_root_access_keys(session: boto3.Session) -> dict[str, Any]:
    """Check if root account has no active access keys.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "GV-04"
    control = "Root Account No Active Access Keys"
    aws_service = "iam"
    severity = "HIGH"

    try:
        iam_client = session.client("iam")
        summary = iam_client.get_account_summary()

        keys_present = summary.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0)
        if keys_present == 0:
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": "Root account has no active access keys",
                "remediation": "",
                "severity": severity,
            }
        else:
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "Root account has active access keys present",
                "remediation": "Delete root account access keys and use IAM roles instead",
                "severity": severity,
            }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "GOVERN",
                "abbreviation": "GV",
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
                "function": "GOVERN",
                "abbreviation": "GV",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }
