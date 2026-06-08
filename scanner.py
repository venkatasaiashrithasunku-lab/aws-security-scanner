import boto3
import json
import os
from datetime import datetime
from checks import iam_checks
from checks import s3_checks
from checks import cloudtrail_checks
from checks import vpc_checks
from checks import guardduty_checks

def run_all_checks():
    print("\n" + "="*60)
    print("   AWS SECURITY MISCONFIGURATION SCANNER")
    print("   Mapped to CIS Benchmarks & NIST CSF")
    print("="*60)
    print(f"   Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60 + "\n")

    all_findings = []

    print("[*] Running IAM checks...")
    all_findings += iam_checks.run_all_checks()

    print("[*] Running S3 checks...")
    all_findings += s3_checks.run_all_checks()

    print("[*] Running CloudTrail checks...")
    all_findings += cloudtrail_checks.run_all_checks()

    print("[*] Running VPC checks...")
    all_findings += vpc_checks.run_all_checks()

    print("[*] Running GuardDuty checks...")
    all_findings += guardduty_checks.run_all_checks()

    print("\n" + "="*60)
    print("   SCAN COMPLETE")
    print("="*60)

    # Count by severity
    critical = [f for f in all_findings if f['severity'] == 'CRITICAL']
    high     = [f for f in all_findings if f['severity'] == 'HIGH']
    medium   = [f for f in all_findings if f['severity'] == 'MEDIUM']
    info     = [f for f in all_findings if f['severity'] == 'INFO']

    print(f"\n   Total findings : {len(all_findings)}")
    print(f"   CRITICAL       : {len(critical)}")
    print(f"   HIGH           : {len(high)}")
    print(f"   MEDIUM         : {len(medium)}")
    print(f"   INFO           : {len(info)}")
    print("\n" + "="*60)

    # Print findings grouped by severity
    for severity, label in [('CRITICAL', critical), ('HIGH', high), ('MEDIUM', medium)]:
        if label:
            print(f"\n[{severity} FINDINGS]")
            print("-"*60)
            for f in label:
                print(f"  Check      : {f['check']}")
                print(f"  Resource   : {f['resource']}")
                print(f"  Action     : {f['recommendation']}")
                print()

    # Save results to JSON
    output_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump({
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_findings': len(all_findings),
            'summary': {
                'CRITICAL': len(critical),
                'HIGH': len(high),
                'MEDIUM': len(medium),
                'INFO': len(info)
            },
            'findings': all_findings
        }, f, indent=2)

    print(f"\n[*] Full results saved to: {output_file}")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_all_checks()