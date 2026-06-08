import boto3

def check_public_buckets():
    findings = []
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append({
                        'check': 'S3 Bucket Publicly Accessible via ACL',
                        'resource': bucket_name,
                        'severity': 'CRITICAL',
                        'recommendation': f'Remove public access from bucket {bucket_name}'
                    })
        except Exception:
            pass
    return findings

def check_bucket_encryption():
    findings = []
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except Exception:
            findings.append({
                'check': 'S3 Bucket Not Encrypted',
                'resource': bucket_name,
                'severity': 'HIGH',
                'recommendation': f'Enable default encryption for bucket {bucket_name}'
            })
    return findings

def check_bucket_versioning():
    findings = []
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', '')
            if status != 'Enabled':
                findings.append({
                    'check': 'S3 Bucket Versioning Not Enabled',
                    'resource': bucket_name,
                    'severity': 'MEDIUM',
                    'recommendation': f'Enable versioning for bucket {bucket_name}'
                })
        except Exception:
            pass
    return findings

def check_public_access_block():
    findings = []
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            block = s3.get_public_access_block(Bucket=bucket_name)
            config = block['PublicAccessBlockConfiguration']
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                findings.append({
                    'check': 'S3 Bucket Public Access Block Not Fully Enabled',
                    'resource': bucket_name,
                    'severity': 'HIGH',
                    'recommendation': f'Enable all public access block settings for bucket {bucket_name}'
                })
        except Exception:
            findings.append({
                'check': 'S3 Bucket Public Access Block Not Configured',
                'resource': bucket_name,
                'severity': 'HIGH',
                'recommendation': f'Configure public access block for bucket {bucket_name}'
            })
    return findings

def run_all_checks():
    findings = []
    findings += check_public_buckets()
    findings += check_bucket_encryption()
    findings += check_bucket_versioning()
    findings += check_public_access_block()
    return findings