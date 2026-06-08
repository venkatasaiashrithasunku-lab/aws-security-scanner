# AWS Security Misconfiguration Scanner

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![AWS](https://img.shields.io/badge/AWS-Security-orange)
![License](https://img.shields.io/badge/License-MIT-green)

Automated AWS security misconfiguration scanner mapped to **CIS Benchmarks Level 1 and 2** and **NIST CSF** controls. Identifies critical security gaps across IAM, S3, CloudTrail, VPC, and GuardDuty with risk-prioritized findings and actionable remediation guidance.

## What It Does

Connects to your AWS account via boto3 and automatically audits your environment for the most common and critical security misconfigurations — the same checks performed manually by cloud security engineers during security assessments.

## Security Checks Performed

| Category | Check | Severity | CIS Reference |
|---|---|---|---|
| IAM | Users without MFA enabled | HIGH | CIS 1.10 |
| IAM | Root account active access keys | CRITICAL | CIS 1.4 |
| IAM | No password policy configured | HIGH | CIS 1.8 |
| IAM | Users with full AdministratorAccess | HIGH | CIS 1.16 |
| S3 | Publicly accessible buckets via ACL | CRITICAL | CIS 2.1.5 |
| S3 | Buckets without default encryption | HIGH | CIS 2.1.1 |
| S3 | Buckets without versioning enabled | MEDIUM | CIS 2.1.3 |
| S3 | Public access block not configured | HIGH | CIS 2.1.4 |
| CloudTrail | CloudTrail not enabled | CRITICAL | CIS 3.1 |
| CloudTrail | Log file validation disabled | MEDIUM | CIS 3.2 |
| CloudTrail | No multi-region trail configured | HIGH | CIS 3.3 |
| CloudTrail | Trail not logging to S3 | HIGH | CIS 3.6 |
| VPC | Default security group has rules | HIGH | CIS 5.4 |
| VPC | VPC Flow Logs not enabled | MEDIUM | CIS 5.1 |
| VPC | Security groups open to world | CRITICAL | CIS 5.2 |
| GuardDuty | GuardDuty not enabled per region | HIGH | AWS Best Practice |
| GuardDuty | High severity findings detected | CRITICAL | AWS Best Practice |

## Installation

Clone the repository:

```bash
git clone https://github.com/venkatasaiashrithasunku-lab/aws-security-scanner.git
cd aws-security-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure AWS credentials:

```bash
aws configure
```

## Usage

```bash
py scanner.py
```

Sample output:
============================================================
AWS SECURITY MISCONFIGURATION SCANNER
Mapped to CIS Benchmarks and NIST CSF
Scan started: 2026-06-08 18:38:43
[] Running IAM checks...
[] Running S3 checks...
[] Running CloudTrail checks...
[] Running VPC checks...
[*] Running GuardDuty checks...
============================================================
SCAN COMPLETE
Total findings : 10
CRITICAL       : 1
HIGH           : 8
MEDIUM         : 1
[CRITICAL FINDINGS]
Check      : CloudTrail Not Enabled
Resource   : account
Action     : Enable CloudTrail to log all AWS API calls

Results are automatically saved to a timestamped JSON file.

## Project Structure
aws-security-scanner/
├── scanner.py               Main entry point
├── requirements.txt         Dependencies
└── checks/
├── iam_checks.py        IAM security checks
├── s3_checks.py         S3 bucket security checks
├── cloudtrail_checks.py CloudTrail configuration checks
├── vpc_checks.py        VPC and security group checks
└── guardduty_checks.py  GuardDuty status checks

## Requirements

- Python 3.12+
- boto3
- AWS credentials with SecurityAudit permissions

## Roadmap

- HTML report with color coded findings
- Azure security checks support
- Slack webhook alerting
- Prisma Cloud integration
- Scheduled scanning via AWS Lambda

## Author

Venkatasai Ashritha
Senior Cloud Security Engineer | AWS · Azure · GCP
LinkedIn: https://www.linkedin.com/in/venkatasaiashritha-295381186