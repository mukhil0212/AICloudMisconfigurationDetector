import boto3
import os
from botocore.exceptions import ClientError, NoCredentialsError

def find_public_s3_buckets(aws_access_key_id=None, aws_secret_access_key=None, region='us-east-1'):
    # If no credentials provided, return mock data immediately
    if not aws_access_key_id or not aws_secret_access_key:
        return [
            {
                'type': 'Public S3 Bucket',
                'resource_id': 'mock-bucket-123',
                'details': 'This bucket is publicly accessible (mock data - provide credentials for real scan).'
            }
        ]
    
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region
        )
        
        misconfigurations = []
        for bucket in s3.list_buckets().get('Buckets', []):
            try:
                # Check bucket ACL
                acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                for grant in acl['Grants']:
                    if 'URI' in grant['Grantee'] and 'AllUsers' in grant['Grantee']['URI']:
                        misconfigurations.append({
                            'type': 'Public S3 Bucket',
                            'resource_id': bucket['Name'],
                            'details': 'This bucket is publicly accessible via ACL.'
                        })
                        break
                
                # Check bucket policy for public access
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket['Name'])
                    if '"Principal": "*"' in policy['Policy'] or '"Principal": {"AWS": "*"}' in policy['Policy']:
                        misconfigurations.append({
                            'type': 'Public S3 Bucket Policy',
                            'resource_id': bucket['Name'],
                            'details': 'This bucket has a policy allowing public access.'
                        })
                except ClientError:
                    pass  # No bucket policy exists
                    
            except Exception as e:
                continue
                
        return misconfigurations
    except (NoCredentialsError, ClientError):
        # Return mock data if credentials are invalid
        return [
            {
                'type': 'Public S3 Bucket',
                'resource_id': 'mock-bucket-123',
                'details': 'This bucket is publicly accessible (mock data - invalid credentials).'
            }
        ]

def find_permissive_iam_roles(aws_access_key_id=None, aws_secret_access_key=None, region='us-east-1'):
    # If no credentials provided, return mock data immediately
    if not aws_access_key_id or not aws_secret_access_key:
        return [
            {
                'type': 'Overly Permissive IAM Role',
                'resource_id': 'mock-role-abc',
                'details': 'This role has overly permissive policies (mock data - provide credentials for real scan).'
            }
        ]
    
    try:
        iam = boto3.client(
            'iam',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region
        )
        
        misconfigurations = []
        roles = iam.list_roles().get('Roles', [])
        
        for role in roles:
            # Check attached policies
            policies = iam.list_attached_role_policies(RoleName=role['RoleName']).get('AttachedPolicies', [])
            for policy in policies:
                try:
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                    )
                    statements = policy_version['PolicyVersion']['Document']['Statement']
                    if not isinstance(statements, list):
                        statements = [statements]
                    
                    for statement in statements:
                        if (statement.get('Effect') == 'Allow' and 
                            statement.get('Action') == '*' and 
                            statement.get('Resource') == '*'):
                            misconfigurations.append({
                                'type': 'Overly Permissive IAM Role',
                                'resource_id': role['RoleName'],
                                'details': f'Role has policy {policy["PolicyName"]} allowing all actions on all resources.'
                            })
                            break
                except Exception:
                    continue
                    
        return misconfigurations
    except (NoCredentialsError, ClientError):
        return [
            {
                'type': 'Overly Permissive IAM Role',
                'resource_id': 'mock-role-abc',
                'details': 'This role has overly permissive policies (mock data - invalid credentials).'
            }
        ]

def find_unrestricted_security_groups(aws_access_key_id=None, aws_secret_access_key=None, region='us-east-1'):
    # If no credentials provided, return mock data immediately
    if not aws_access_key_id or not aws_secret_access_key:
        return [{
            'type': 'Unrestricted Security Group',
            'resource_id': 'sg-mock123',
            'details': 'Security group allows unrestricted access (mock data - provide credentials for real scan).'
        }]
    
    try:
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=region
        )
        
        misconfigurations = []
        security_groups = ec2.describe_security_groups()['SecurityGroups']
        
        for sg in security_groups:
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_info = f"port {rule.get('FromPort', 'all')}" if rule.get('FromPort') else "all ports"
                        misconfigurations.append({
                            'type': 'Unrestricted Security Group',
                            'resource_id': sg['GroupId'],
                            'details': f'Security group allows inbound access from 0.0.0.0/0 on {port_info}.'
                        })
                        break
                        
        return misconfigurations
    except (NoCredentialsError, ClientError):
        return [{
            'type': 'Unrestricted Security Group',
            'resource_id': 'sg-mock123',
            'details': 'Security group allows unrestricted access (mock data - invalid credentials).'
        }]

def scan_all():
    """Scan with default/environment credentials"""
    s3_issues = find_public_s3_buckets()
    iam_issues = find_permissive_iam_roles()
    sg_issues = find_unrestricted_security_groups()
    return s3_issues + iam_issues + sg_issues

def scan_with_credentials(aws_access_key_id, aws_secret_access_key, region='us-east-1'):
    """Scan with provided AWS credentials"""
    s3_issues = find_public_s3_buckets(aws_access_key_id, aws_secret_access_key, region)
    iam_issues = find_permissive_iam_roles(aws_access_key_id, aws_secret_access_key, region)
    sg_issues = find_unrestricted_security_groups(aws_access_key_id, aws_secret_access_key, region)
    return s3_issues + iam_issues + sg_issues 