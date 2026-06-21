import logging
from remediation.engine import RemediationEngine
from remediation.workflows.guided_workflow import WorkflowState

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

import json

def main():
    print("\n--- Initializing Remediation Engine ---")
    engine = RemediationEngine()

    print("\n--- Scenario 1: Critical Insight triggering Automated Action ---")
    critical_insight = {
        "title": "Malware Outbreak Detected",
        "type": "vulnerability",
        "severity": "critical",
        "asset_id": "10.0.0.101"
    }
    
    engine.policy_engine.epsilon = 0.0
    state_key = engine.policy_engine._get_state_key(critical_insight)
    engine.policy_engine.q_table[state_key] = {
        "pb_network_isolate_01": 1.0, 
        "pb_patch_guidance_01": 0.0,
        "pb_generic_investigate": 0.0
    }

    result = engine.process_insight(critical_insight)
    print(f"Initial Result: {result}")
    
    if result.startswith("AWAITING_APPROVAL"):
        execution_id = result.split(":")[1]
        print(f"\n[+] Analyst reviews the alert context... and approves.")
        res1 = engine.approve_action(execution_id, "SOC_ANALYST")
        print(f"SOC Approval Result: {res1}")
        
        print(f"\n[+] Legal reviews the impact... and approves.")
        res2 = engine.approve_action(execution_id, "LEGAL")
        print(f"Legal Approval Result: {res2}")

    print("\n--- Scenario 2: High Severity Insight triggering Guided Workflow ---")
    high_insight = {
        "title": "Missing Security Patch",
        "type": "vulnerability",
        "severity": "high",
        "asset_id": "10.0.0.102"
    }
    
    workflow_id = engine.process_insight(high_insight)
    print(f"Workflow ID: {workflow_id}")

    print("\n--- Scenario 3: Pre-Execution Simulation for Supply Chain Incident ---")
    supply_chain_insight = {
        "title": "Compromised Vendor Portal",
        "type": "vendor_portal_vulnerability",
        "severity": "high",
        "target_endpoint": "api.vendor.com/v1/auth"
    }
    
    engine.policy_engine.epsilon = 0.0
    state_key = engine.policy_engine._get_state_key(supply_chain_insight)
    engine.policy_engine.q_table[state_key] = {"pb_supply_chain_controls": 1.0}

    sim_result = engine.simulate_insight(supply_chain_insight)
    print("Simulation Report:")
    print(json.dumps(sim_result, indent=2))
    
    print("\nExecuting the Supply Chain Incident after reviewing simulation...")
    result = engine.process_insight(supply_chain_insight)
    print(f"Execution Result: {result}")

    print("\n--- Scenario 4: Complex Incident SOAR Escalation ---")
    complex_insight = {
        "title": "Ransomware Lateral Movement",
        "type": "complex_incident",
        "severity": "critical"
    }
    
    state_key = engine.policy_engine._get_state_key(complex_insight)
    engine.policy_engine.q_table[state_key] = {"pb_soar_escalation": 1.0}

    result = engine.process_insight(complex_insight)
    print(f"Initial Result: {result}")
    
    if result.startswith("AWAITING_APPROVAL"):
        execution_id = result.split(":")[1]
        print(f"\n[+] SOC Analyst reviews the context... determines it's a false positive, and rejects it.")
        res = engine.reject_action(execution_id, "SOC_ANALYST", reason="False positive based on recent configuration change.")
        print(f"Rejection Result: {res}")

if __name__ == "__main__":
    main()
