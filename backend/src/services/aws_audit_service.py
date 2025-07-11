import boto3
import json
from datetime import datetime, timedelta
from botocore.exceptions import ClientError, NoCredentialsError

class AWSAuditService:
    def __init__(self):
        self.findings = []
        self.compliance_checks = {
            'iam': self._audit_iam,
            's3': self._audit_s3,
            'ec2': self._audit_ec2,
            'vpc': self._audit_vpc,
            'cloudtrail': self._audit_cloudtrail,
            'config': self._audit_config
        }
    
    def run_audit(self, aws_config):
        """Run comprehensive AWS security audit"""
        try:
            # Configure AWS credentials
            if 'access_key' in aws_config and 'secret_key' in aws_config:
                session = boto3.Session(
                    aws_access_key_id=aws_config['access_key'],
                    aws_secret_access_key=aws_config['secret_key'],
                    region_name=aws_config.get('region', 'us-east-1')
                )
            else:
                # Use default credentials (IAM role, environment variables, etc.)
                session = boto3.Session(region_name=aws_config.get('region', 'us-east-1'))
            
            results = {
                'timestamp': datetime.now().isoformat(),
                'region': aws_config.get('region', 'us-east-1'),
                'audit_results': {},
                'summary': {}
            }
            
            # Run audits for each service
            services_to_audit = aws_config.get('services', ['iam', 's3', 'ec2', 'vpc'])
            
            for service in services_to_audit:
                if service in self.compliance_checks:
                    try:
                        results['audit_results'][service] = self.compliance_checks[service](session)
                    except Exception as e:
                        results['audit_results'][service] = {
                            'status': 'error',
                            'error': str(e)
                        }
            
            # Calculate overall compliance score
            results['compliance_score'] = self._calculate_compliance_score(results['audit_results'])
            results['summary'] = self._generate_summary(results['audit_results'])
            
            return results
            
        except NoCredentialsError:
            return {'error': 'AWS credentials not found or invalid'}
        except Exception as e:
            return {'error': f'AWS audit failed: {str(e)}'}
    
    def _audit_iam(self, session):
        """Audit IAM configuration"""
        try:
            iam = session.client('iam')
            findings = []
            recommendations = []
            
            # Check for root account usage
            try:
                credential_report = iam.generate_credential_report()
                # Note: In practice, you'd wait for the report and then get it
                # This is a simplified version
                findings.append({
                    'check': 'Root Account Usage',
                    'status': 'warning',
                    'description': 'Check root account access keys and usage'
                })
            except ClientError:
                pass
            
            # Check password policy
            try:
                password_policy = iam.get_account_password_policy()
                policy = password_policy['PasswordPolicy']
                
                if policy.get('MinimumPasswordLength', 0) < 14:
                    findings.append({
                        'check': 'Password Policy',
                        'status': 'failed',
                        'description': 'Minimum password length should be at least 14 characters'
                    })
                
                if not policy.get('RequireNumbers', False):
                    findings.append({
                        'check': 'Password Policy',
                        'status': 'failed',
                        'description': 'Password policy should require numbers'
                    })
                
                if not policy.get('RequireSymbols', False):
                    findings.append({
                        'check': 'Password Policy',
                        'status': 'failed',
                        'description': 'Password policy should require symbols'
                    })
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    findings.append({
                        'check': 'Password Policy',
                        'status': 'failed',
                        'description': 'No password policy configured'
                    })
            
            # Check for users with console access but no MFA
            try:
                users = iam.list_users()['Users']
                for user in users[:10]:  # Limit to first 10 users
                    username = user['UserName']
                    
                    # Check if user has console access
                    try:
                        login_profile = iam.get_login_profile(UserName=username)
                        # User has console access, check for MFA
                        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                        if not mfa_devices:
                            findings.append({
                                'check': 'MFA Configuration',
                                'status': 'failed',
                                'description': f'User {username} has console access but no MFA enabled'
                            })
                    except ClientError:
                        # User doesn't have console access
                        pass
            except ClientError:
                pass
            
            # Check for overly permissive policies
            try:
                policies = iam.list_policies(Scope='Local', MaxItems=20)['Policies']
                for policy in policies:
                    policy_arn = policy['Arn']
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_doc = policy_version['PolicyVersion']['Document']
                    if isinstance(policy_doc, str):
                        policy_doc = json.loads(policy_doc)
                    
                    # Check for wildcard permissions
                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            if '*' in actions or (isinstance(actions, list) and '*' in actions):
                                if '*' in resources or (isinstance(resources, list) and '*' in resources):
                                    findings.append({
                                        'check': 'Overly Permissive Policies',
                                        'status': 'warning',
                                        'description': f'Policy {policy["PolicyName"]} has wildcard permissions'
                                    })
            except ClientError:
                pass
            
            return {
                'status': 'completed',
                'findings': findings,
                'recommendations': recommendations,
                'checks_performed': len(findings)
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _audit_s3(self, session):
        """Audit S3 configuration"""
        try:
            s3 = session.client('s3')
            findings = []
            
            # List buckets
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets[:10]:  # Limit to first 10 buckets
                bucket_name = bucket['Name']
                
                # Check bucket public access
                try:
                    bucket_acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in bucket_acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group':
                            uri = grantee.get('URI', '')
                            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                findings.append({
                                    'check': 'S3 Bucket Public Access',
                                    'status': 'failed',
                                    'description': f'Bucket {bucket_name} has public access via ACL'
                                })
                except ClientError:
                    pass
                
                # Check bucket policy for public access
                try:
                    bucket_policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(bucket_policy['Policy'])
                    
                    for statement in policy_doc.get('Statement', []):
                        principal = statement.get('Principal')
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            findings.append({
                                'check': 'S3 Bucket Policy',
                                'status': 'failed',
                                'description': f'Bucket {bucket_name} has public access via bucket policy'
                            })
                except ClientError:
                    pass
                
                # Check bucket encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append({
                            'check': 'S3 Bucket Encryption',
                            'status': 'warning',
                            'description': f'Bucket {bucket_name} does not have encryption enabled'
                        })
                
                # Check bucket versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append({
                            'check': 'S3 Bucket Versioning',
                            'status': 'warning',
                            'description': f'Bucket {bucket_name} does not have versioning enabled'
                        })
                except ClientError:
                    pass
                
                # Check bucket logging
                try:
                    logging = s3.get_bucket_logging(Bucket=bucket_name)
                    if 'LoggingEnabled' not in logging:
                        findings.append({
                            'check': 'S3 Bucket Logging',
                            'status': 'warning',
                            'description': f'Bucket {bucket_name} does not have access logging enabled'
                        })
                except ClientError:
                    pass
            
            return {
                'status': 'completed',
                'findings': findings,
                'buckets_audited': len(buckets[:10])
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _audit_ec2(self, session):
        """Audit EC2 configuration"""
        try:
            ec2 = session.client('ec2')
            findings = []
            
            # Check security groups
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check for overly permissive inbound rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                            findings.append({
                                'check': 'Security Group Rules',
                                'status': 'warning' if rule.get('FromPort') in [80, 443] else 'failed',
                                'description': f'Security group {sg_name} ({sg_id}) allows inbound traffic from 0.0.0.0/0 on ports {port_range}'
                            })
            
            # Check instances
            instances = ec2.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Check if instance has public IP
                    if instance.get('PublicIpAddress'):
                        findings.append({
                            'check': 'EC2 Public Access',
                            'status': 'warning',
                            'description': f'Instance {instance_id} has a public IP address'
                        })
                    
                    # Check instance metadata service configuration
                    if instance.get('MetadataOptions', {}).get('HttpTokens') != 'required':
                        findings.append({
                            'check': 'EC2 Metadata Service',
                            'status': 'warning',
                            'description': f'Instance {instance_id} does not require IMDSv2'
                        })
            
            return {
                'status': 'completed',
                'findings': findings,
                'security_groups_audited': len(security_groups)
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _audit_vpc(self, session):
        """Audit VPC configuration"""
        try:
            ec2 = session.client('ec2')
            findings = []
            
            # Check VPC flow logs
            vpcs = ec2.describe_vpcs()['Vpcs']
            flow_logs = ec2.describe_flow_logs()['FlowLogs']
            
            vpc_with_flow_logs = set(fl['ResourceId'] for fl in flow_logs if fl['ResourceType'] == 'VPC')
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                if vpc_id not in vpc_with_flow_logs:
                    findings.append({
                        'check': 'VPC Flow Logs',
                        'status': 'warning',
                        'description': f'VPC {vpc_id} does not have flow logs enabled'
                    })
            
            # Check NACLs for overly permissive rules
            nacls = ec2.describe_network_acls()['NetworkAcls']
            for nacl in nacls:
                nacl_id = nacl['NetworkAclId']
                
                for entry in nacl.get('Entries', []):
                    if entry.get('CidrBlock') == '0.0.0.0/0' and entry.get('RuleAction') == 'allow':
                        findings.append({
                            'check': 'Network ACL Rules',
                            'status': 'warning',
                            'description': f'Network ACL {nacl_id} has permissive rules allowing 0.0.0.0/0'
                        })
            
            return {
                'status': 'completed',
                'findings': findings,
                'vpcs_audited': len(vpcs)
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _audit_cloudtrail(self, session):
        """Audit CloudTrail configuration"""
        try:
            cloudtrail = session.client('cloudtrail')
            findings = []
            
            # Check if CloudTrail is enabled
            trails = cloudtrail.describe_trails()['trailList']
            
            if not trails:
                findings.append({
                    'check': 'CloudTrail Configuration',
                    'status': 'failed',
                    'description': 'No CloudTrail trails configured'
                })
            else:
                for trail in trails:
                    trail_name = trail['Name']
                    
                    # Check if trail is logging
                    status = cloudtrail.get_trail_status(Name=trail_name)
                    if not status.get('IsLogging', False):
                        findings.append({
                            'check': 'CloudTrail Logging',
                            'status': 'failed',
                            'description': f'CloudTrail {trail_name} is not actively logging'
                        })
                    
                    # Check if trail logs to S3
                    if not trail.get('S3BucketName'):
                        findings.append({
                            'check': 'CloudTrail S3 Logging',
                            'status': 'failed',
                            'description': f'CloudTrail {trail_name} is not configured to log to S3'
                        })
                    
                    # Check if trail has log file validation enabled
                    if not trail.get('LogFileValidationEnabled', False):
                        findings.append({
                            'check': 'CloudTrail Log Validation',
                            'status': 'warning',
                            'description': f'CloudTrail {trail_name} does not have log file validation enabled'
                        })
            
            return {
                'status': 'completed',
                'findings': findings,
                'trails_audited': len(trails)
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _audit_config(self, session):
        """Audit AWS Config configuration"""
        try:
            config = session.client('config')
            findings = []
            
            # Check if Config is enabled
            try:
                config_recorders = config.describe_configuration_recorders()['ConfigurationRecorders']
                delivery_channels = config.describe_delivery_channels()['DeliveryChannels']
                
                if not config_recorders:
                    findings.append({
                        'check': 'AWS Config',
                        'status': 'warning',
                        'description': 'AWS Config is not enabled'
                    })
                else:
                    for recorder in config_recorders:
                        recorder_name = recorder['name']
                        
                        # Check if recorder is recording
                        status = config.describe_configuration_recorder_status(
                            ConfigurationRecorderNames=[recorder_name]
                        )['ConfigurationRecordersStatus'][0]
                        
                        if not status.get('recording', False):
                            findings.append({
                                'check': 'AWS Config Recording',
                                'status': 'warning',
                                'description': f'Config recorder {recorder_name} is not recording'
                            })
                
                if not delivery_channels:
                    findings.append({
                        'check': 'AWS Config Delivery',
                        'status': 'warning',
                        'description': 'No Config delivery channels configured'
                    })
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchConfigurationRecorderException':
                    findings.append({
                        'check': 'AWS Config',
                        'status': 'warning',
                        'description': 'AWS Config is not configured'
                    })
            
            return {
                'status': 'completed',
                'findings': findings
            }
            
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _calculate_compliance_score(self, audit_results):
        """Calculate overall compliance score"""
        total_checks = 0
        passed_checks = 0
        
        for service, results in audit_results.items():
            if isinstance(results, dict) and 'findings' in results:
                findings = results['findings']
                total_checks += len(findings)
                
                for finding in findings:
                    if finding.get('status') == 'passed':
                        passed_checks += 1
                    elif finding.get('status') == 'warning':
                        passed_checks += 0.5  # Partial credit for warnings
        
        if total_checks == 0:
            return 100  # No issues found
        
        return round((passed_checks / total_checks) * 100)
    
    def _generate_summary(self, audit_results):
        """Generate audit summary"""
        summary = {
            'total_services_audited': len(audit_results),
            'critical_findings': 0,
            'warning_findings': 0,
            'passed_checks': 0,
            'recommendations': []
        }
        
        for service, results in audit_results.items():
            if isinstance(results, dict) and 'findings' in results:
                for finding in results['findings']:
                    status = finding.get('status')
                    if status == 'failed':
                        summary['critical_findings'] += 1
                    elif status == 'warning':
                        summary['warning_findings'] += 1
                    elif status == 'passed':
                        summary['passed_checks'] += 1
        
        # Generate recommendations based on findings
        if summary['critical_findings'] > 0:
            summary['recommendations'].append('Address critical security findings immediately')
        if summary['warning_findings'] > 0:
            summary['recommendations'].append('Review and remediate warning-level findings')
        
        summary['recommendations'].extend([
            'Enable AWS Config for continuous compliance monitoring',
            'Implement AWS Security Hub for centralized security findings',
            'Regular security audits and penetration testing'
        ])
        
        return summary

