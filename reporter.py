"""NIST CSF 2.0 Compliance Report Generator.

This module builds the CSV report and prints colored terminal summary.
"""

import csv
import logging
import os
from datetime import date
from typing import Any

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# ANSI color codes for terminal output
ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[92m"
ANSI_RED = "\033[91m"
ANSI_YELLOW = "\033[93m"
ANSI_BOLD = "\033[1m"


def generate_report(
    results: list[dict[str, Any]],
    output_dir: str,
    fail_only: bool = False,
) -> str:
    """Generate CSV report from check results.

    Args:
        results: List of check result dictionaries
        output_dir: Directory to write CSV file
        fail_only: If True, only include FAIL results in detail section

    Returns:
        Path to the generated CSV file
    """
    # Generate filename with current date
    today = date.today().strftime("%Y-%m-%d")
    filename = f"nist_csf_report_{today}.csv"
    filepath = os.path.join(output_dir, filename)

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Calculate summaries
    function_summary = _calculate_function_summary(results)
    overall_summary = _calculate_overall_summary(results)

    # Write CSV
    with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

        # Section 1: Detail rows
        writer.writerow(
            [
                "Function",
                "Abbreviation",
                "Control_ID",
                "Control",
                "AWS_Service",
                "Severity",
                "Status",
                "Detail",
                "Remediation",
            ]
        )

        for result in results:
            if fail_only and result.get("status") != "FAIL":
                continue
            writer.writerow(
                [
                    result.get("function", ""),
                    result.get("abbreviation", ""),
                    result.get("control_id", ""),
                    result.get("control", ""),
                    result.get("aws_service", ""),
                    result.get("severity", ""),
                    result.get("status", ""),
                    result.get("detail", ""),
                    result.get("remediation", ""),
                ]
            )

        # Section 2: Blank row separator
        writer.writerow([])

        # Section 3: Per-function summary
        writer.writerow(
            [
                "Function",
                "Total_Checks",
                "Passed",
                "Failed",
                "Unknown",
                "Compliance_Pct",
            ]
        )

        for func_name, summary in function_summary.items():
            writer.writerow(
                [
                    func_name,
                    summary["total"],
                    summary["passed"],
                    summary["failed"],
                    summary["unknown"],
                    summary["compliance_pct"],
                ]
            )

        # Section 4: Blank row separator
        writer.writerow([])

        # Section 5: Overall summary
        writer.writerow(
            [
                "OVERALL",
                overall_summary["total"],
                overall_summary["passed"],
                overall_summary["failed"],
                overall_summary["unknown"],
                overall_summary["compliance_pct"],
            ]
        )

    return filepath


def _calculate_function_summary(
    results: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Calculate per-function summary statistics.

    Args:
        results: List of check result dictionaries

    Returns:
        Dictionary mapping function name to summary stats
    """
    summary: dict[str, dict[str, Any]] = {}

    for result in results:
        func = result.get("function", "UNKNOWN")
        if func not in summary:
            summary[func] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "unknown": 0,
            }

        summary[func]["total"] += 1
        status = result.get("status", "UNKNOWN")
        if status == "PASS":
            summary[func]["passed"] += 1
        elif status == "FAIL":
            summary[func]["failed"] += 1
        else:
            summary[func]["unknown"] += 1

    # Calculate compliance percentage
    for func in summary:
        total = summary[func]["total"]
        passed = summary[func]["passed"]
        if total > 0:
            summary[func]["compliance_pct"] = round((passed / total) * 100, 1)
        else:
            summary[func]["compliance_pct"] = 0.0

    return summary


def _calculate_overall_summary(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate overall summary statistics.

    Args:
        results: List of check result dictionaries

    Returns:
        Dictionary with overall summary stats
    """
    total = len(results)
    passed = sum(1 for r in results if r.get("status") == "PASS")
    failed = sum(1 for r in results if r.get("status") == "FAIL")
    unknown = sum(1 for r in results if r.get("status") == "UNKNOWN")

    compliance_pct = round((passed / total) * 100, 1) if total > 0 else 0.0

    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "unknown": unknown,
        "compliance_pct": compliance_pct,
    }


def print_summary(results: list[dict[str, Any]]) -> None:
    """Print colored summary table to terminal.

    Args:
        results: List of check result dictionaries
    """
    # Calculate summaries
    function_summary = _calculate_function_summary(results)
    overall_summary = _calculate_overall_summary(results)

    # Print colored detail rows
    print(f"\n{ANSI_BOLD}=== NIST CSF 2.0 Compliance Check Results ==={ANSI_RESET}\n")

    for result in results:
        status = result.get("status", "UNKNOWN")
        control_id = result.get("control_id", "")
        control = result.get("control", "")
        detail = result.get("detail", "")

        # Select color based on status
        if status == "PASS":
            color = ANSI_GREEN
            symbol = "✓"
        elif status == "FAIL":
            color = ANSI_RED
            symbol = "✗"
        else:
            color = ANSI_YELLOW
            symbol = "?"

        print(f"{color}{symbol} {control_id}: {control}{ANSI_RESET}")
        print(f"   {color}{status}{ANSI_RESET} — {detail}\n")

    # Print function summary
    print(f"\n{ANSI_BOLD}--- Per-Function Summary ---{ANSI_RESET}\n")

    for func_name in ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]:
        if func_name in function_summary:
            summary = function_summary[func_name]
            pct = summary["compliance_pct"]

            # Color based on compliance percentage
            if pct >= 75:
                color = ANSI_GREEN
            elif pct >= 50:
                color = ANSI_YELLOW
            else:
                color = ANSI_RED

            print(
                f"{color}{func_name}{ANSI_RESET}: {summary['passed']}/{summary['total']} "
                f"passed ({pct}%) — "
                f"PASS:{summary['passed']} FAIL:{summary['failed']} UNKNOWN:{summary['unknown']}"
            )

    # Print overall summary
    print(f"\n{ANSI_BOLD}--- Overall Summary ---{ANSI_RESET}\n")

    overall_pct = overall_summary["compliance_pct"]
    if overall_pct >= 75:
        color = ANSI_GREEN
    elif overall_pct >= 50:
        color = ANSI_YELLOW
    else:
        color = ANSI_RED

    print(
        f"{ANSI_BOLD}OVERALL{ANSI_RESET}: {color}{overall_summary['passed']}/{overall_summary['total']} "
        f"passed ({overall_pct}%){ANSI_RESET}"
    )
    print(
        f"   PASS: {overall_summary['passed']} | "
        f"FAIL: {ANSI_RED}{overall_summary['failed']}{ANSI_RESET} | "
        f"UNKNOWN: {ANSI_YELLOW}{overall_summary['unknown']}{ANSI_RESET}\n"
    )
