import boto3

def check_cloudtrail_enabled():
    findings = []
    cloudtrail = boto3.client('cloudtrail')
    
    trails = cloudtrail.describe_trails()['trailList']
    if not trails:
        findings.append({
            'check': 'CloudTrail Not Enabled',
            'resource': 'account',
            'severity': 'CRITICAL',
            'recommendation': 'Enable CloudTrail to log all AWS API calls across all regions'
        })
        return findings
    
    for trail in trails:
        trail_name = trail['Name']
        status = cloudtrail.get_trail_status(Name=trail_name)
        if not status.get('IsLogging', False):
            findings.append({
                'check': 'CloudTrail Logging Disabled',
                'resource': trail_name,
                'severity': 'CRITICAL',
                'recommendation': f'Enable logging for CloudTrail trail {trail_name}'
            })
    return findings

def check_cloudtrail_log_validation():
    findings = []
    cloudtrail = boto3.client('cloudtrail')
    
    trails = cloudtrail.describe_trails()['trailList']
    for trail in trails:
        trail_name = trail['Name']
        if not trail.get('LogFileValidationEnabled', False):
            findings.append({
                'check': 'CloudTrail Log File Validation Disabled',
                'resource': trail_name,
                'severity': 'MEDIUM',
                'recommendation': f'Enable log file validation for trail {trail_name} to detect tampering'
            })
    return findings

def check_cloudtrail_multi_region():
    findings = []
    cloudtrail = boto3.client('cloudtrail')
    
    trails = cloudtrail.describe_trails()['trailList']
    multi_region = any(t.get('IsMultiRegionTrail', False) for t in trails)
    if not multi_region:
        findings.append({
            'check': 'No Multi-Region CloudTrail Configured',
            'resource': 'account',
            'severity': 'HIGH',
            'recommendation': 'Configure at least one multi-region CloudTrail to capture all activity'
        })
    return findings

def check_cloudtrail_s3_logging():
    findings = []
    cloudtrail = boto3.client('cloudtrail')
    
    trails = cloudtrail.describe_trails()['trailList']
    for trail in trails:
        trail_name = trail['Name']
        if not trail.get('S3BucketName'):
            findings.append({
                'check': 'CloudTrail Not Logging to S3',
                'resource': trail_name,
                'severity': 'HIGH',
                'recommendation': f'Configure S3 bucket logging for trail {trail_name}'
            })
    return findings

def run_all_checks():
    findings = []
    findings += check_cloudtrail_enabled()
    findings += check_cloudtrail_log_validation()
    findings += check_cloudtrail_multi_region()
    findings += check_cloudtrail_s3_logging()
    return findings