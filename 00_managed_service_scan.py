#!/usr/bin/env python3
"""
Managed Service Scanner - Scans AWS managed service permissions and configurations
"""

import boto3
import json
import logging
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_managed_services():
    """Scan managed service security configurations"""
    
    # Initialize AWS clients
    org = boto3.client('organizations')
    iam = boto3.client('iam')
    sts = boto3.client('sts')
    
    findings = []
    
    try:
        # Scan SCPs (Service Control Policies)
        scps = scan_scp_configurations(org)
        findings.extend(scps)
        
        # Scan permission boundaries
        boundaries = scan_permission_boundaries(iam)
        findings.extend(boundaries)
        
        # Scan managed policies
        managed_policies = scan_managed_policies(iam)
        findings.extend(managed_policies)
        
        # Scan IAM roles and users
        iam_resources = scan_iam_resources(iam)
        findings.extend(iam_resources)
        
    except ClientError as e:
        logger.error(f"Error scanning managed services: {e}")
        
    return findings

def scan_scp_configurations(org):
    """Scan Service Control Policies for security issues"""
    findings = []
    
    try:
        # Get all roots
        roots = org.list_roots()['Roots']
        
        for root in roots:
            root_id = root['Id']
            
            # Get SCPs attached to root
            try:
                attached_policies = org.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
                
                for policy in attached_policies:
                    if policy['Type'] == 'SERVICE_CONTROL_POLICY':
                        # Get policy content
                        policy_content = org.describe_policy(PolicyId=policy['Id'])['Policy']['Content']
                        
                        # Check for overly permissive policies
                        if check_overly_permissive_scp(policy_content):
                            findings.append({
                                'type': 'scp_overly_permissive',
                                'resource_id': policy['Id'],
                                'severity': 'CRITICAL',
                                'description': f'SCP {policy["Name"]} allows excessive permissions'
                            })
                            
            except ClientError:
                pass
                
    except ClientError:
        pass
        
    return findings

def check_overly_permissive_scp(policy_content):
    """Check if SCP content is overly permissive"""
    # This would parse the SCP JSON and look for dangerous permissions
    # Simplified implementation - in practice this would be more complex
    try:
        import json
        policy = json.loads(policy_content)
        
        # Look for wildcard permissions or broad actions
        for statement in policy.get('Statement', []):
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
                
            for action in actions:
                if action == '*' or action.endswith(':*'):
                    return True
                    
    except Exception:
        pass
        
    return False

def scan_permission_boundaries(iam):
    """Scan IAM permission boundaries"""
    findings = []
    
    try:
        # List users
        users = iam.list_users()['Users']
        
        for user in users:
            # Check if user has a permissions boundary
            if 'PermissionsBoundary' not in user:
                findings.append({
                    'type': 'user_no_boundary',
                    'resource_id': user['Arn'],
                    'severity': 'HIGH',
                    'description': f'User {user["UserName"]} has no permission boundary'
                })
                
        # List roles
        roles = iam.list_roles()['Roles']
        
        for role in roles:
            if 'PermissionsBoundary' not in role:
                findings.append({
                    'type': 'role_no_boundary',
                    'resource_id': role['Arn'],
                    'severity': 'HIGH',
                    'description': f'Role {role["RoleName"]} has no permission boundary'
                })
                
    except ClientError:
        pass
        
    return findings

def scan_managed_policies(iam):
    """Scan managed policies for issues"""
    findings = []
    
    try:
        # List attached managed policies
        attached_policies = iam.list_attached_managed_policies()['AttachedPolicies']
        
        for policy in attached_policies:
            # Check for overly permissive managed policies
            if is_overly_permissive_policy(policy['PolicyName']):
                findings.append({
                    'type': 'managed_policy_overly_permissive',
                    'resource_id': policy['PolicyArn'],
                    'severity': 'MEDIUM',
                    'description': f'Managed policy {policy["PolicyName"]} allows excessive permissions'
                })
                
    except ClientError:
        pass
        
    return findings

def is_overly_permissive_policy(policy_name):
    """Check if a managed policy name suggests overly permissive access"""
    # This would be more sophisticated in practice
    overly_permissive_names = [
        'AdministratorAccess',
        'PowerUserAccess',
        'RootAccess',
        'FullAccess'
    ]
    
    return any(name in policy_name for name in overly_permissive_names)

def scan_iam_resources(iam):
    """Scan IAM resources for security issues"""
    findings = []
    
    try:
        # Check for admin-like permissions
        users = iam.list_users()['Users']
        
        for user in users:
            # Check attached policies
            attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
            
            for policy in attached_policies:
                if 'AdministratorAccess' in policy['PolicyName']:
                    findings.append({
                        'type': 'user_admin_access',
                        'resource_id': user['Arn'],
                        'severity': 'CRITICAL',
                        'description': f'User {user["UserName"]} has AdministratorAccess policy'
                    })
                    
    except ClientError:
        pass
        
    return findings

def main():
    """Main execution function"""
    print("🔍 Scanning managed service permissions...")
    
    findings = scan_managed_services()
    
    # Save results
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"managed_service_scan_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'findings': findings,
            'total_findings': len(findings)
        }, f, indent=2, default=str)
        
    print(f"✅ Managed service scan completed. Results saved to: {output_file}")
    return findings

if __name__ == "__main__":
    main()
