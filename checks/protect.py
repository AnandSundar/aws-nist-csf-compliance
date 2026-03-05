"""NIST CSF 2.0 PROTECT Function Checks.

This module implements security checks for the PROTECT function which safeguards
to manage cybersecurity risk and limit impact.

Checks implemented:
  PR-01: No IAM users have inline policies attached
  PR-02: At least one customer-managed KMS key (CMK) is enabled
  PR-03: S3 account-level block public access are fully enabled
  PR-04: At least one S3 bucket has versioning enabled
"""

import logging
from typing import Any

import botocore.exceptions
import boto3

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


def run_checks(session: boto3.Session, region: str) -> list[dict[str, Any]]:
    """Run all PROTECT function security checks.

    Args:
        session: boto3 Session object for making AWS API calls
        region: AWS region to scan

    Returns:
        List of check result dictionaries conforming to the check schema
    """
    results = []

    results.append(_check_no_inline_policies(session))
    results.append(_check_kms_cmk(session))
    results.append(_check_s3_block_public_access(session))
    results.append(_check_s3_versioning(session))

    return results


def _check_no_inline_policies(session: boto3.Session) -> dict[str, Any]:
    """Check that no IAM users have inline policies attached.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "PR-01"
    control = "No IAM Users with Inline Policies"
    aws_service = "iam"
    severity = "MEDIUM"

    try:
        iam_client = session.client("iam")
        users = iam_client.list_users(MaxItems=1000)

        users_with_inline = []

        if "Users" in users and users["Users"]:
            for user in users["Users"]:
                username = user["UserName"]
                try:
                    inline_policies = iam_client.list_user_policies(UserName=username)
                    if inline_policies.get("PolicyNames"):
                        users_with_inline.append(username)
                except botocore.exceptions.ClientError:
                    # Skip users we can't access
                    pass

        if not users_with_inline:
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": "No IAM users have inline policies attached",
                "remediation": "",
                "severity": severity,
            }
        else:
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": f"{len(users_with_inline)} IAM user(s) have inline policies: {', '.join(users_with_inline[:3])}",
                "remediation": "Convert inline policies to managed policies for better governance",
                "severity": severity,
            }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
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
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_kms_cmk(session: boto3.Session) -> dict[str, Any]:
    """Check if at least one customer-managed KMS key (CMK) is enabled.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "PR-02"
    control = "KMS Customer Master Key (CMK) Enabled"
    aws_service = "kms"
    severity = "MEDIUM"

    try:
        kms_client = session.client("kms")
        keys = kms_client.list_keys(Limit=100)

        cmk_count = 0
        if "Keys" in keys and keys["Keys"]:
            for key in keys["Keys"]:
                try:
                    key_info = kms_client.describe_key(KeyId=key["KeyId"])
                    key_metadata = key_info.get("KeyMetadata", {})
                    # Count CMKs (not AWS managed) that are enabled
                    if (
                        key_metadata.get("KeyManager") == "CUSTOMER"
                        and key_metadata.get("KeyState") == "Enabled"
                    ):
                        cmk_count += 1
                except botocore.exceptions.ClientError:
                    pass

        if cmk_count > 0:
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "PASS",
                "detail": f"{cmk_count} customer-managed KMS key(s) are enabled",
                "remediation": "",
                "severity": severity,
            }

        return {
            "function": "PROTECT",
            "abbreviation": "PR",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No customer-managed KMS keys are enabled",
            "remediation": "Create customer-managed KMS keys for encryption at rest",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
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
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }


def _check_s3_block_public_access(session: boto3.Session) -> dict[str, Any]:
    """Check if S3 account-level block public access is fully enabled.

    Returns:
        Check result dictionary with function, abbreviation, control_id, control,
        aws_service, status, detail, remediation, and severity keys
    """
    control_id = "PR-03"
    control = "S3 Block Public Access Enabled"
    aws_service = "s3"
    severity = "HIGH"

    try:
        s3_client = session.client("s3")
        block_config = s3_client.get_public_access_block(
            Bucket=""  # Account-level setting
        )

        if "PublicAccessBlockConfiguration" in block_config:
            config = block_config["PublicAccessBlockConfiguration"]

            all_enabled = (
                config.get("BlockPublicAcls", False)
                and config.get("BlockPublicPolicy", False)
                and config.get("IgnorePublicAcls", False)
                and config.get("RestrictPublicBuckets", False)
            )

            if all_enabled:
                return {
                    "function": "PROTECT",
                    "abbreviation": "PR",
                    "control_id": control_id,
                    "control": control,
                    "aws_service": aws_service,
                    "status": "PASS",
                    "detail": "S3 block public access is fully enabled at account level",
                    "remediation": "",
                    "severity": severity,
                }
            else:
                disabled = []
                if not config.get("BlockPublicAcls"):
                    disabled.append("BlockPublicAcls")
                if not config.get("BlockPublicPolicy"):
                    disabled.append("BlockPublicPolicy")
                if not config.get("IgnorePublicAcls"):
                    disabled.append("IgnorePublicAcls")
                if not config.get("RestrictPublicBuckets"):
                    disabled.append("RestrictPublicBuckets")

                return {
                    "function": "PROTECT",
                    "abbreviation": "PR",
                    "control_id": control_id,
                    "control": control,
                    "aws_service": aws_service,
                    "status": "FAIL",
                    "detail": f"S3 block public access is not fully enabled. Disabled: {', '.join(disabled)}",
                    "remediation": "Enable all four S3 block public access settings at account level",
                    "severity": severity,
                }

        return {
            "function": "PROTECT",
            "abbreviation": "PR",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "S3 block public access is not configured at account level",
            "remediation": "Enable account-level S3 block public access settings",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": "Permission denied — check IAM policy",
                "remediation": "",
                "severity": severity,
            }
        elif error_code == "NoSuchPublicAccessBlockConfiguration":
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "FAIL",
                "detail": "S3 block public access is not configured at account level",
                "remediation": "Enable account-level S3 block public access settings",
                "severity": severity,
            }
        else:
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
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
    control_id = "PR-04"
    control = "S3 Bucket Versioning Enabled"
    aws_service = "s3"
    severity = "MEDIUM"

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
                            "function": "PROTECT",
                            "abbreviation": "PR",
                            "control_id": control_id,
                            "control": control,
                            "aws_service": aws_service,
                            "status": "PASS",
                            "detail": f"S3 bucket '{bucket_name}' has versioning enabled",
                            "remediation": "",
                            "severity": severity,
                        }
                except botocore.exceptions.ClientError:
                    pass

        return {
            "function": "PROTECT",
            "abbreviation": "PR",
            "control_id": control_id,
            "control": control,
            "aws_service": aws_service,
            "status": "FAIL",
            "detail": "No S3 buckets have versioning enabled",
            "remediation": "Enable S3 bucket versioning for data protection",
            "severity": severity,
        }

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "AccessDeniedException":
            return {
                "function": "PROTECT",
                "abbreviation": "PR",
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
                "function": "PROTECT",
                "abbreviation": "PR",
                "control_id": control_id,
                "control": control,
                "aws_service": aws_service,
                "status": "UNKNOWN",
                "detail": f"AWS API error: {error_code}",
                "remediation": "",
                "severity": severity,
            }
