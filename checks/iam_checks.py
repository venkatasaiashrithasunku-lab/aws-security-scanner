import boto3

def check_iam_users_without_mfa():
    findings = []
    iam = boto3.client('iam')
    
    users = iam.list_users()['Users']
    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        if not mfa_devices:
            findings.append({
                'check': 'IAM User Without MFA',
                'resource': username,
                'severity': 'HIGH',
                'recommendation': f'Enable MFA for IAM user {username}'
            })
    return findings

def check_root_access_keys():
    findings = []
    iam = boto3.client('iam')
    
    summary = iam.get_account_summary()['SummaryMap']
    if summary.get('AccountAccessKeysPresent', 0) > 0:
        findings.append({
            'check': 'Root Account Has Active Access Keys',
            'resource': 'root',
            'severity': 'CRITICAL',
            'recommendation': 'Delete root account access keys immediately'
        })
    return findings

def check_password_policy():
    findings = []
    iam = boto3.client('iam')
    
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        if policy.get('MinimumPasswordLength', 0) < 14:
            findings.append({
                'check': 'Weak Password Policy - Minimum Length',
                'resource': 'account-password-policy',
                'severity': 'MEDIUM',
                'recommendation': 'Set minimum password length to 14 or more characters'
            })
        if not policy.get('RequireSymbols', False):
            findings.append({
                'check': 'Weak Password Policy - No Symbols Required',
                'resource': 'account-password-policy',
                'severity': 'MEDIUM',
                'recommendation': 'Enable symbol requirement in password policy'
            })
    except iam.exceptions.NoSuchEntityException:
        findings.append({
            'check': 'No Password Policy Set',
            'resource': 'account-password-policy',
            'severity': 'HIGH',
            'recommendation': 'Create and enforce an IAM password policy'
        })
    return findings

def check_admin_users():
    findings = []
    iam = boto3.client('iam')
    
    users = iam.list_users()['Users']
    for user in users:
        username = user['UserName']
        policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for policy in policies:
            if policy['PolicyName'] == 'AdministratorAccess':
                findings.append({
                    'check': 'User Has Full Administrator Access',
                    'resource': username,
                    'severity': 'HIGH',
                    'recommendation': f'Review and restrict admin access for user {username}'
                })
    return findings

def run_all_checks():
    findings = []
    findings += check_iam_users_without_mfa()
    findings += check_root_access_keys()
    findings += check_password_policy()
    findings += check_admin_users()
    return findings