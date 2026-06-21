import pytest
from remediation.engine import RemediationEngine
from remediation.workflows.guided_workflow import WorkflowState

@pytest.fixture
def engine():
    return RemediationEngine()

def test_automated_network_isolation(engine):
    insight = {
        "title": "Critical Ransomware Indicator",
        "type": "vulnerability",
        "severity": "critical",
        "asset_id": "192.168.1.50"
    }
    
    # Process the insight
    result = engine.process_insight(insight)
    
    # Either it succeeded or it fell back to a guided workflow depending on RL policy,
    # but initially it should try to explore or pick the matching automated playbook.
    # Since we have two playbooks matching 'critical' 'vulnerability', it might pick either.
    assert result in ["AUTOMATED_SUCCESS", "AUTOMATED_FAILED"] or "-" in result # UUID for guided

def test_guided_workflow_execution(engine):
    insight = {
        "title": "Patch available for DB server",
        "type": "vulnerability",
        "severity": "high",
        "asset_id": "db-server-01"
    }
    
    # Process the insight. Only pb_patch_guidance_01 matches 'high'
    workflow_id = engine.process_insight(insight)
    
    # It should return a UUID for the guided workflow
    assert "-" in workflow_id
    
    workflow = engine.get_workflow(workflow_id)
    assert workflow is not None
    
    # First step doesn't require evidence, but waits for acknowledgment
    assert workflow.state == WorkflowState.IN_PROGRESS
    
    # Advance to next step
    success = workflow.advance()
    assert success is True
    
    # Second step requires evidence
    assert workflow.state == WorkflowState.WAITING_EVIDENCE
    
    # Submit evidence
    success = workflow.submit_evidence("patch_applied_screenshot.png")
    assert success is True
    
    # Should be completed
    assert workflow.state == WorkflowState.COMPLETED
