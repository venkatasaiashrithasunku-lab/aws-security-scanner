import boto3

def check_default_vpc_security_groups():
    findings = []
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    try:
        vpcs = ec2.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])['Vpcs']
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            sgs = ec2.describe_security_groups(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]},
                    {'Name': 'group-name', 'Values': ['default']}
                ]
            )['SecurityGroups']
            for sg in sgs:
                if sg['IpPermissions'] or sg['IpPermissionsEgress']:
                    findings.append({
                        'check': 'Default VPC Security Group Has Rules',
                        'resource': sg['GroupId'],
                        'severity': 'HIGH',
                        'recommendation': f'Remove all rules from default security group {sg["GroupId"]} in VPC {vpc_id}'
                    })
    except Exception as e:
        findings.append({
            'check': 'VPC Security Group Check Error',
            'resource': 'unknown',
            'severity': 'INFO',
            'recommendation': f'Error checking VPC security groups: {str(e)}'
        })
    return findings

def check_vpc_flow_logs():
    findings = []
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            flow_logs = ec2.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )['FlowLogs']
            if not flow_logs:
                findings.append({
                    'check': 'VPC Flow Logs Not Enabled',
                    'resource': vpc_id,
                    'severity': 'MEDIUM',
                    'recommendation': f'Enable VPC Flow Logs for VPC {vpc_id} to capture network traffic'
                })
    except Exception as e:
        findings.append({
            'check': 'VPC Flow Logs Check Error',
            'resource': 'unknown',
            'severity': 'INFO',
            'recommendation': f'Error checking VPC flow logs: {str(e)}'
        })
    return findings

def check_open_security_groups():
    findings = []
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    try:
        sgs = ec2.describe_security_groups()['SecurityGroups']
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        if from_port in [22, 3389] or from_port == 'All':
                            findings.append({
                                'check': 'Security Group Open to World on Sensitive Port',
                                'resource': f'{sg_id} ({sg_name})',
                                'severity': 'CRITICAL',
                                'recommendation': f'Restrict inbound access on port {from_port} in security group {sg_id}'
                            })
    except Exception as e:
        findings.append({
            'check': 'Security Group Check Error',
            'resource': 'unknown',
            'severity': 'INFO',
            'recommendation': f'Error checking security groups: {str(e)}'
        })
    return findings

def run_all_checks():
    findings = []
    findings += check_default_vpc_security_groups()
    findings += check_vpc_flow_logs()
    findings += check_open_security_groups()
    return findings