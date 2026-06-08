import boto3

def check_guardduty_enabled():
    findings = []
    
    regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
    
    for region in regions:
        guardduty = boto3.client('guardduty', region_name=region)
        try:
            detectors = guardduty.list_detectors()['DetectorIds']
            if not detectors:
                findings.append({
                    'check': 'GuardDuty Not Enabled',
                    'resource': f'region:{region}',
                    'severity': 'HIGH',
                    'recommendation': f'Enable GuardDuty in region {region} for threat detection'
                })
            else:
                for detector_id in detectors:
                    detector = guardduty.get_detector(DetectorId=detector_id)
                    if detector['Status'] != 'ENABLED':
                        findings.append({
                            'check': 'GuardDuty Detector Disabled',
                            'resource': f'{region}/{detector_id}',
                            'severity': 'HIGH',
                            'recommendation': f'Enable GuardDuty detector {detector_id} in region {region}'
                        })
        except Exception as e:
            findings.append({
                'check': 'GuardDuty Check Error',
                'resource': f'region:{region}',
                'severity': 'INFO',
                'recommendation': f'Could not check GuardDuty in {region}: {str(e)}'
            })
    return findings

def check_guardduty_findings():
    findings = []
    
    regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
    
    for region in regions:
        guardduty = boto3.client('guardduty', region_name=region)
        try:
            detectors = guardduty.list_detectors()['DetectorIds']
            for detector_id in detectors:
                finding_ids = guardduty.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={
                        'Criterion': {
                            'severity': {
                                'Gte': 7
                            }
                        }
                    }
                )['FindingIds']
                
                if finding_ids:
                    findings.append({
                        'check': 'GuardDuty High Severity Findings Detected',
                        'resource': f'{region}/{detector_id}',
                        'severity': 'CRITICAL',
                        'recommendation': f'Investigate {len(finding_ids)} high severity GuardDuty findings in {region}'
                    })
        except Exception:
            pass
    return findings

def run_all_checks():
    findings = []
    findings += check_guardduty_enabled()
    findings += check_guardduty_findings()
    return findings