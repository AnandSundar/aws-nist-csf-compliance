"""NIST CSF 2.0 Compliance Dashboard - CLI Entry Point.

This tool scans an AWS account using read-only Boto3 API calls and produces
a NIST CSF 2.0 compliance gap report as a structured CSV file.
"""

import argparse
import logging
import os
import sys
from datetime import datetime

import boto3

import reporter
from checks import ALL_MODULES
from config import FUNCTION_META

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configure logging from environment variable
LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")
logging.getLogger().setLevel(getattr(logging, LOG_LEVEL.upper(), logging.WARNING))


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="NIST CSF 2.0 Compliance Dashboard - AWS Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--profile",
        type=str,
        default="default",
        help="AWS named profile (default: default)",
    )

    parser.add_argument(
        "--region",
        type=str,
        default="us-east-1",
        help="AWS region to scan (default: us-east-1)",
    )

    parser.add_argument(
        "--output",
        type=str,
        default=".",
        help="Directory to write CSV (default: current directory)",
    )

    parser.add_argument(
        "--function",
        type=str,
        choices=["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"],
        help="Run only one function (optional)",
    )

    parser.add_argument(
        "--severity",
        type=str,
        choices=["HIGH", "MEDIUM", "LOW"],
        help="Filter output to only specified severity checks",
    )

    parser.add_argument(
        "--fail-only",
        action="store_true",
        help="Show/write only FAIL results in CSV",
    )

    return parser.parse_args()


def create_session(profile: str, region: str) -> boto3.Session:
    """Create boto3 session with specified profile and region.

    Args:
        profile: AWS profile name
        region: AWS region

    Returns:
        boto3 Session object

    Raises:
        Exception: If session creation fails
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        # Verify credentials by making a simple API call
        sts_client = session.client("sts")
        sts_client.get_caller_identity()
        return session
    except Exception as e:
        logger.error(f"Failed to create AWS session: {e}")
        raise


def run_all_checks(
    session: boto3.Session,
    region: str,
    function_filter: str | None = None,
) -> list[dict]:
    """Run all NIST CSF 2.0 security checks.

    Args:
        session: boto3 Session object
        region: AWS region to scan
        function_filter: Optional function to run (e.g., "GOVERN")

    Returns:
        List of all check results
    """
    all_results = []
    functions_to_run = []

    # Determine which functions to run
    if function_filter:
        # Map function name to module
        function_map = {
            "GOVERN": "govern",
            "IDENTIFY": "identify",
            "PROTECT": "protect",
            "DETECT": "detect",
            "RESPOND": "respond",
            "RECOVER": "recover",
        }
        module_name = function_map.get(function_filter)
        if module_name:
            for module in ALL_MODULES:
                if module.__name__ == f"checks.{module_name}":
                    functions_to_run.append((function_filter, module))
                    break
    else:
        # Run all functions
        function_order = [
            "GOVERN",
            "IDENTIFY",
            "PROTECT",
            "DETECT",
            "RESPOND",
            "RECOVER",
        ]
        for module in ALL_MODULES:
            for func_name in function_order:
                if func_name in FUNCTION_META:
                    functions_to_run.append((func_name, module))
                    break

    # Run checks for each function
    for func_name, module in functions_to_run:
        check_count = _get_check_count(module)

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] Running {func_name} checks...", end=" ")

        try:
            results = module.run_checks(session, region)
            all_results.extend(results)
            print(f"✓ {len(results)} checks complete")
        except Exception as e:
            logger.error(f"Error running {func_name} checks: {e}")
            print(f"✗ Error: {e}")

    return all_results


def _get_check_count(module) -> int:
    """Get the number of checks a module will run.

    Args:
        module: Check module

    Returns:
        Number of checks (approximate based on function)
    """
    module_name = module.__name__
    if "govern" in module_name or "identify" in module_name:
        return 4
    elif "protect" in module_name or "detect" in module_name:
        return 4
    elif "respond" in module_name or "recover" in module_name:
        return 3
    return 0


def filter_results(
    results: list[dict],
    severity_filter: str | None = None,
    fail_only: bool = False,
) -> list[dict]:
    """Filter results based on criteria.

    Args:
        results: List of check results
        severity_filter: Optional severity filter (HIGH, MEDIUM, LOW)
        fail_only: If True, only return FAIL results

    Returns:
        Filtered list of results
    """
    filtered = []

    for result in results:
        # Apply severity filter
        if severity_filter and result.get("severity") != severity_filter:
            continue

        # Apply fail-only filter
        if fail_only and result.get("status") != "FAIL":
            continue

        filtered.append(result)

    return filtered


def main() -> int:
    """Main entry point for the CLI.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    args = parse_args()

    print(f"\n{'='*60}")
    print(f"NIST CSF 2.0 Compliance Dashboard")
    print(f"{'='*60}")
    print(f"Profile: {args.profile}")
    print(f"Region: {args.region}")
    print(f"Output: {args.output}")
    if args.function:
        print(f"Function: {args.function}")
    if args.severity:
        print(f"Severity Filter: {args.severity}")
    if args.fail_only:
        print(f"Fail Only: Yes")
    print(f"{'='*60}\n")

    # Create AWS session
    try:
        session = create_session(args.profile, args.region)
    except Exception as e:
        print(f"Error: Failed to create AWS session: {e}")
        return 1

    # Run all checks
    print(f"Starting NIST CSF 2.0 compliance scan...\n")
    all_results = run_all_checks(session, args.region, args.function)

    if not all_results:
        print("Error: No checks were executed.")
        return 1

    # Filter results based on criteria
    filtered_results = filter_results(
        all_results,
        severity_filter=args.severity,
        fail_only=args.fail_only,
    )

    # Generate CSV report
    try:
        csv_path = reporter.generate_report(all_results, args.output, args.fail_only)
        print(f"\nReport saved: {csv_path}")
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        print(f"Error: Failed to generate report: {e}")
        return 1

    # Print colored summary
    if not args.fail_only:
        reporter.print_summary(all_results)
    else:
        # For fail-only, show filtered summary
        reporter.print_summary(filtered_results)

    # Return appropriate exit code
    failed_count = sum(1 for r in all_results if r.get("status") == "FAIL")
    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
