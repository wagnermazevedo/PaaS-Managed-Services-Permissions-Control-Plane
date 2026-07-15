#!/usr/bin/env python3
"""
Managed Service Planner - Generates remediation plans for managed service permissions
"""

import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_managed_service_plan(scan_results):
    """Generate remediation plan from scan results"""
    
    actions = []
    
    # Process findings and create remediation actions
    for finding in scan_results.get('findings', []):
        action = {
            'id': f"action_{len(actions) + 1}",
            'type': finding['type'],
            'resource_id': finding['resource_id'],
            'severity': finding['severity'],
            'description': finding['description'],
            'action': '',
            'status': 'pending'
        }
        
        # Generate specific remediation actions based on finding type
        if finding['type'] == 'scp_overly_permissive':
            action['action'] = f"Review and restrict SCP {finding['resource_id']} permissions"
            
        elif finding['type'] == 'user_no_boundary':
            action['action'] = f"Attach permission boundary to user {finding['resource_id']}"
            
        elif finding['type'] == 'role_no_boundary':
            action['action'] = f"Attach permission boundary to role {finding['resource_id']}"
            
        elif finding['type'] == 'managed_policy_overly_permissive':
            action['action'] = f"Review managed policy {finding['resource_id']} for excessive permissions"
            
        elif finding['type'] == 'user_admin_access':
            action['action'] = f"Remove AdministratorAccess from user {finding['resource_id']}"
            
        actions.append(action)
    
    plan = {
        'timestamp': datetime.now().isoformat(),
        'plan_type': 'managed_service_remediation',
        'actions': actions,
        'total_actions': len(actions),
        'recommendations': []
    }
    
    return plan

def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python 01_managed_service_plan.py <scan_results_file>")
        sys.exit(1)
        
    scan_file = sys.argv[1]
    
    print("📋 Generating managed service remediation plan...")
    
    # Load scan results
    with open(scan_file, 'r') as f:
        scan_results = json.load(f)
    
    # Generate plan
    plan = generate_managed_service_plan(scan_results)
    
    # Save plan
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f"managed_service_plan_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(plan, f, indent=2, default=str)
        
    print(f"✅ Managed service plan generated. Results saved to: {output_file}")
    return plan

if __name__ == "__main__":
    main()
