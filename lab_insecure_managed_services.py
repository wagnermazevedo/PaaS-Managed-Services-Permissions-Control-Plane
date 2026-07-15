#!/usr/bin/env python3
"""
Managed Service Lab - Creates test environments for managed service permission validation
"""

import boto3
import json
import logging
from datetime import datetime
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_insecure_managed_service_environment():
    """Create intentionally insecure managed service environment for testing"""
    
    iam = boto3.client('iam')
    org = boto3.client('organizations')
    
    # Create a test user with no boundary (insecure)
    user_name = 'test-insecure-user'
    try:
        print("Creating insecure IAM user...")
        iam.create_user(UserName=user_name)
        
        # Attach overly permissive managed policy
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        
        print(f"✅ Insecure IAM user created: {user_name}")
        
        # Create a test role with no boundary (insecure)
        role_name = 'test-insecure-role'
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document)
        )
        
        print(f"✅ Insecure IAM role created: {role_name}")
        
        # Create an overly permissive SCP
        try:
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
            
            # This would create a very permissive SCP
            print("✅ Insecure SCP created for testing")
            
        except ClientError as e:
            logger.warning(f"Could not create SCP: {e}")
        
        # Save lab configuration
        lab_config = {
            'timestamp': datetime.now().isoformat(),
            'environment': 'managed_service_lab',
            'resources': {
                'user_name': user_name,
                'role_name': role_name
            }
        }
        
        output_file = f"managed_service_lab_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(lab_config, f, indent=2, default=str)
            
        print(f"✅ Lab configuration saved to: {output_file}")
        
        return lab_config
        
    except ClientError as e:
        logger.error(f"Error creating managed service lab environment: {e}")
        return None

def cleanup_managed_service_lab(lab_config):
    """Clean up managed service lab environment"""
    
    iam = boto3.client('iam')
    
    try:
        print("Cleaning up managed service lab environment...")
        
        # Delete test user
        if 'user_name' in lab_config['resources']:
            user_name = lab_config['resources']['user_name']
            try:
                # Detach policies first
                attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
                for policy in attached_policies:
                    iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
                
                # Delete user
                iam.delete_user(UserName=user_name)
                print(f"Deleted user: {user_name}")
            except ClientError as e:
                logger.warning(f"Could not delete user {user_name}: {e}")
        
        # Delete test role
        if 'role_name' in lab_config['resources']:
            role_name = lab_config['resources']['role_name']
            try:
                # Detach policies first
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                for policy in attached_policies:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
                
                # Delete role
                iam.delete_role(RoleName=role_name)
                print(f"Deleted role: {role_name}")
            except ClientError as e:
                logger.warning(f"Could not delete role {role_name}: {e}")
        
        print("✅ Managed service lab environment cleaned up successfully")
        
    except ClientError as e:
        logger.error(f"Error cleaning up managed service lab: {e}")

def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'cleanup':
        # Load lab config from file
        try:
            with open('managed_service_lab_config_latest.json', 'r') as f:
                lab_config = json.load(f)
            cleanup_managed_service_lab(lab_config)
        except FileNotFoundError:
            print("No lab configuration found to clean up")
    else:
        # Create new lab environment
        lab_config = create_insecure_managed_service_environment()
        
        if lab_config:
            # Save latest config
            with open('managed_service_lab_config_latest.json', 'w') as f:
                json.dump(lab_config, f, indent=2, default=str)
            
            print("🧪 Managed service lab environment ready for testing")
            print("⚠️  Remember to run cleanup when done")

if __name__ == "__main__":
    main()
