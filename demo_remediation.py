import logging
from remediation.engine import RemediationEngine
from remediation.workflows.guided_workflow import WorkflowState

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

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
    
    # Since RL policy explores, we'll force it to exploit by setting epsilon=0 
    # and biasing the Q-table for the automated playbook.
    engine.policy_engine.epsilon = 0.0
    state_key = engine.policy_engine._get_state_key(critical_insight)
    engine.policy_engine.q_table[state_key] = {
        "pb_network_isolate_01": 1.0, 
        "pb_patch_guidance_01": 0.0,
        "pb_generic_investigate": 0.0
    }

    result = engine.process_insight(critical_insight)
    print(f"Result: {result}")


    print("\n--- Scenario 2: High Severity Insight triggering Guided Workflow ---")
    high_insight = {
        "title": "Missing Security Patch",
        "type": "vulnerability",
        "severity": "high",
        "asset_id": "10.0.0.102"
    }
    
    workflow_id = engine.process_insight(high_insight)
    print(f"Workflow ID: {workflow_id}")
    
    workflow = engine.get_workflow(workflow_id)
    if workflow:
        print(f"Current State: {workflow.state}")
        print("Advancing step 1...")
        workflow.advance()
        print(f"Current State: {workflow.state}")
        
        print("Submitting evidence for step 2...")
        workflow.submit_evidence("proof_of_patch.jpg")
        print(f"Current State: {workflow.state}")

if __name__ == "__main__":
    main()
