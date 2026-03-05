# 🛡️ NIST CSF 2.0 Compliance Dashboard

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-Boto3-orange)](https://aws.amazon.com/boto3/)
[![NIST CSF](https://img.shields.io/badge/NIST%20CSF-2.0-green)](https://csrc.nist.gov/publications/detail/sp/800-53/final)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](https://opensource.org/licenses/MIT)
[![Read Only](https://img.shields.io/badge/AWS%20Access-Read--Only-brightgreen)](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html)

> Scan your AWS environment against the NIST Cybersecurity Framework 2.0 and get a compliance gap report in under 60 seconds — no infrastructure changes required.

---

## What Is This?

Companies running software in the cloud (AWS) need to prove they follow security best practices. Auditors, clients, and regulators increasingly ask for proof of compliance with NIST CSF — a framework published by the US National Institute of Standards and Technology. Most teams have no easy way to check their compliance status quickly.

This tool automatically scans an AWS account, checks ~20 security controls, and produces a report card — organized by the 6 NIST CSF 2.0 pillars — showing what's passing, what's failing, and exactly what to fix. Think of it like a health check for your cloud security posture.

NIST CSF 2.0 (released February 2024) is the most referenced security framework in job postings. The 2024 update added a new pillar called "GOVERN" — focused on leadership-level accountability for cybersecurity risk — making this framework relevant not just to engineers, but to CTOs and boards.

---

## 🎬 See It In Action

```terminal
$ python main.py --profile default --region us-east-1 --output ./reports/

[10:42:30] Starting NIST CSF 2.0 compliance scan...
[10:42:30] AWS Account: 123456789012 | Region: us-east-1

[10:42:31] Running GOVERN checks... ✓ 4 checks complete
[10:42:32] Running IDENTIFY checks... ✓ 4 checks complete
[10:42:33] Running PROTECT checks... ✓ 4 checks complete
[10:42:35] Running DETECT checks... ✓ 4 checks complete
[10:42:36] Running RESPOND checks... ✓ 3 checks complete
[10:42:37] Running RECOVER checks... ✓ 3 checks complete

──────────────────────────────────────────────────────────
NIST CSF 2.0 COMPLIANCE SUMMARY
──────────────────────────────────────────────────────────
Function Checks ✅ Pass ❌ Fail ❓ Unknown Score
───────── ────── ─────── ─────── ───────── ─────
GOVERN 4 2 2 0 50.0%
IDENTIFY 4 4 0 0 100.0%
PROTECT 4 3 1 0 75.0%
DETECT 4 4 0 0 100.0%
RESPOND 3 1 2 0 33.3%
RECOVER 3 2 1 0 66.7%
───────── ────── ─────── ─────── ───────── ─────
OVERALL 22 16 6 0 72.7%
──────────────────────────────────────────────────────────

Report saved: ./reports/nist_csf_report_2026-03-04.csv
```

> **Note:** Terminal output uses ANSI color codes — PASS in green, FAIL in red, UNKNOWN in yellow. No third-party libraries required.

---

## 🏗️ How It Works

The tool runs as a simple CLI that orchestrates a series of read-only checks against AWS APIs. Each check module focuses on one NIST CSF function, and the results are aggregated into a CSV report.

```
┌─────────────────────────────────────────────────────────────┐
│ nist-csf-dashboard                                          │
│                                                              │
│ CLI (main.py)                                               │
│ │                                                            │
│ ▼                                                            │
│ ┌───────────────────────────────────────────┐               │
│ │ Check Modules (checks/)                   │               │
│ │ govern.py identify.py protect.py         │               │
│ │ detect.py respond.py recover.py          │               │
│ └───────────────────────────────────────────┘               │
│ │                                                            │
│ ▼ (read-only Boto3 API calls)                               │
│ ┌───────────────────────────────────────────┐               │
│ │ AWS Services                             │               │
│ │ IAM GuardDuty Config CloudTrail           │               │
│ │ SecurityHub KMS S3 Backup Lambda          │               │
│ └───────────────────────────────────────────┘               │
│ │                                                            │
│ ▼                                                            │
│ reporter.py → nist_csf_report_YYYY-MM-DD.csv               │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 The 6 NIST CSF 2.0 Functions

NIST CSF 2.0 organizes cybersecurity activity into 6 functions. Here's what each one means in plain English, and which AWS services this tool checks:

| # | Function | Abbr | Plain English Meaning | AWS Services Checked | Checks |
|---|----------|------|-----------------------|----------------------|--------|
| 1 | **GOVERN** | GV | "Does your leadership have cybersecurity rules and accountability in place?" | IAM, AWS Organizations | 4 |
| 2 | **IDENTIFY** | ID | "Do you know what you have and what could go wrong?" | AWS Config, IAM Access Analyzer, CloudTrail | 4 |
| 3 | **PROTECT** | PR | "Are you doing the basics to prevent attacks?" | IAM, KMS, S3 | 4 |
| 4 | **DETECT** | DE | "Will you notice if something goes wrong?" | GuardDuty, Security Hub, CloudTrail, CloudWatch | 4 |
| 5 | **RESPOND** | RS | "Do you have systems in place to react to an attack?" | EventBridge, SNS, Lambda | 3 |
| 6 | **RECOVER** | RC | "Can you get back to normal after an incident?" | AWS Backup, CloudFormation, S3 | 3 |

> 💡 **Why GOVERN is new and important:** NIST CSF 1.1 (the previous version) only had 5 functions. Version 2.0, released February 2024, added GOVERN as the 6th — recognizing that cybersecurity failure is often a leadership and policy problem, not just a technical one.

---

## 📊 Sample Report Output

Below is an example of what the CSV report looks like when opened in any spreadsheet tool:

| Function | Control_ID | Control | AWS_Service | Severity | Status | Detail | Remediation |
|----------|------------|---------|-------------|----------|--------|--------|-------------|
| GOVERN | GV-01 | IAM Password Policy | iam | MEDIUM | ✅ PASS | Password policy enforces 14+ character minimum | — |
| GOVERN | GV-02 | Root Account MFA | iam | HIGH | ❌ FAIL | Root account MFA is not enabled | Enable MFA on the root account immediately via IAM console |
| GOVERN | GV-04 | Root Access Keys | iam | HIGH | ✅ PASS | No active root access keys found | — |
| IDENTIFY | ID-01 | Config Recorder | config | MEDIUM | ✅ PASS | AWS Config recorder is active in us-east-1 | — |
| PROTECT | PR-03 | S3 Block Public Access | s3 | HIGH | ❌ FAIL | Account-level S3 block public access is not fully enabled | Enable all 4 S3 block public access settings at account level |
| DETECT | DE-01 | GuardDuty Enabled | guardduty | HIGH | ✅ PASS | GuardDuty detector is active and enabled | — |
| RESPOND | RS-01 | EventBridge Rules | events | LOW | ❌ FAIL | No EventBridge rules found in us-east-1 | Create at least one EventBridge rule to automate incident response |
| RECOVER | RC-01 | AWS Backup Plan | backup | MEDIUM | ✅ PASS | 2 backup plans found | — |

> **Note:** The full CSV also includes a per-function compliance score summary and an overall score row — making it easy to track progress over time or include in audit documentation.

---

## 📈 Compliance Score Breakdown

Below is an example compliance score breakdown generated from a sample AWS account scan. Your scores will vary based on your configuration.

```
GOVERN    [██████████░░░░░░░░░░░] 50.0% ⚠️
IDENTIFY  [████████████████████] 100.0% ✅
PROTECT   [███████████████░░░░░░] 75.0% ⚠️
DETECT    [████████████████████] 100.0% ✅
RESPOND   [███████░░░░░░░░░░░░░░] 33.3% ❌
RECOVER   [█████████████░░░░░░░░] 66.7% ⚠️
─────────────────────────────────────────
OVERALL   [██████████████░░░░░░░] 72.7% ⚠️
```

**Legend:**
- ✅ = 90–100% (Compliant)
- ⚠️ = 50–89% (Needs Attention)
- ❌ = 0–49% (Critical Gap)

---

## 🚀 Quick Start

1. **Clone the repo**
   ```bash
   git clone https://github.com/your-username/nist-csf-dashboard.git
   cd nist-csf-dashboard
   ```

2. **Install dependencies (just one package)**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure AWS credentials**
   ```bash
   aws configure --profile myprofile
   ```

4. **Run a full scan**
   ```bash
   python main.py --profile myprofile --region us-east-1 --output ./reports/
   ```

5. **Open your report**
   ```bash
   ./reports/nist_csf_report_2026-03-04.csv
   ```

---

## ⚙️ CLI Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | default | AWS named profile from `~/.aws/credentials` |
| `--region` | string | us-east-1 | AWS region to scan |
| `--output` | path | . | Directory to save the CSV report |
| `--function` | string | (all) | Run only one function: GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, or RECOVER |
| `--severity` | string | (all) | Filter checks by severity: HIGH, MEDIUM, or LOW |
| `--fail-only` | flag | false | Only include FAIL results in the output CSV |

**Usage Examples:**

```bash
# Run only DETECT checks
python main.py --profile prod --region us-west-2 --function DETECT

# Show only HIGH severity failures
python main.py --profile prod --severity HIGH --fail-only

# Full scan, save to custom folder
python main.py --profile prod --region eu-west-1 --output ./audits/q1-2026/
```

---

## 🔐 Required AWS Permissions

This tool only reads data — it never creates, modifies, or deletes anything in your AWS account. The following IAM policy grants the exact read-only permissions required:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NISTCSFDashboardReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListUserPolicies",
        "iam:GetAccessKeyLastUsed",
        "organizations:DescribeOrganization",
        "config:DescribeConfigurationRecorders",
        "config:DescribeDeliveryChannels",
        "access-analyzer:ListAnalyzers",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "kms:ListKeys",
        "kms:DescribeKey",
        "s3:GetAccountPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "s3:GetBucketVersioning",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "securityhub:GetFindings",
        "cloudwatch:DescribeAlarms",
        "events:ListRules",
        "sns:ListTopics",
        "lambda:ListFunctions",
        "backup:ListBackupPlans",
        "cloudformation:ListStacks"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Tip:** Create a dedicated IAM user or role with this policy attached. Never attach overly broad administrative permissions — least privilege matters.

---

## 📁 Project Structure

```
nist-csf-dashboard/
│
├── main.py                  # Entry point — CLI flags, orchestration, progress output
├── config.py                # NIST CSF function metadata (names, abbreviations, descriptions)
│
├── checks/                  # One module per NIST CSF function
│   ├── __init__.py          # Exports ALL_MODULES list for auto-discovery
│   ├── govern.py            # GV: IAM password policy, root MFA, Organizations, access keys
│   ├── identify.py          # ID: Config recorder, Access Analyzer, CloudTrail
│   ├── protect.py           # PR: IAM inline policies, KMS, S3 public access, versioning
│   ├── detect.py            # DE: GuardDuty, Security Hub, CloudTrail active, CloudWatch alarms
│   ├── respond.py           # RS: EventBridge rules, SNS topics, Lambda functions
│   └── recover.py           # RC: AWS Backup, CloudFormation stacks, S3 versioning
│
├── reporter.py              # Builds CSV with detail rows + per-function + overall summary
├── requirements.txt         # boto3 only
└── README.md
```

---

## 🔧 Technical Specifications

| Spec | Detail |
|------|--------|
| Language | Python 3.11+ |
| AWS SDK | boto3 (read-only calls) |
| Dependencies | boto3, botocore only |
| Execution time | < 60 seconds on a typical AWS account |
| Output format | CSV (compatible with Excel, Google Sheets, any BI tool) |
| AWS access type | Read-only — zero writes, zero mutations |
| Checks implemented | ~22 across 6 NIST CSF 2.0 functions |
| Severity levels | HIGH / MEDIUM / LOW per check |
| Error handling | All API failures caught — no crashes, graceful UNKNOWN status |
| CLI framework | argparse (standard library — no Click, no Typer) |
| Color output | ANSI escape codes (no rich/colorama needed) |

---

## 🔒 Security Design Principles

- **Read-Only by Design** — Every AWS API call uses the minimum permission needed. The tool can never modify, create, or delete any resource.
- **No Credential Storage** — Uses the AWS named profile system. No credentials are ever written to disk by this tool.
- **Graceful Failure** — If a permission is missing, the check is marked UNKNOWN and the scan continues. The tool never crashes mid-run.
- **Idempotent** — Running the tool 100 times produces the same result. It has no side effects on your AWS environment.

---

## 🔍 Interpreting Your Results

| Status | What It Means | What To Do |
|--------|---------------|------------|
| ✅ PASS | The control is in place and working as expected | No action needed — maintain the configuration |
| ❌ FAIL | The control is missing or misconfigured | Read the Remediation column for a specific fix |
| ❓ UNKNOWN | The tool couldn't verify the control (usually a permissions issue) | Add the missing IAM permission from the permissions section and re-run |

> 💡 **Tip for audits:** A FAIL is not a crisis — it's a prioritized to-do list. Sort by Severity = HIGH first. Fix those. Re-run the tool. Repeat until your OVERALL score is above 90%.

---

## 🗺️ Roadmap

| Status | Feature | Description |
|--------|---------|-------------|
| 🔜 Planned | HTML Report | Generate a styled HTML dashboard from the same data |
| 🔜 Planned | Slack Webhook | Post compliance summary to a Slack channel on scan completion |
| 🔜 Planned | Multi-Account | Scan all accounts in an AWS Organization in one run |
| 💡 Idea | Trend Tracking | Compare reports over time and show score change per function |
| 💡 Idea | CI/CD Integration | Run as a GitHub Actions step on every infrastructure change |

---

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.

---

Built by [Anand Sundar](https://github.com/anandsundar) ·  
Inspired by real-world cloud security engineering ·  
NIST CSF 2.0 reference: https://doi.org/10.6028/NIST.CSWP.29
