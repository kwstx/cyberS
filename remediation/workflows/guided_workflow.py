import logging
import uuid
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class WorkflowState:
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING_EVIDENCE = "WAITING_EVIDENCE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class GuidedWorkflow:
    """
    Manages stateful, step-by-step workflows requiring human interaction.
    """
    def __init__(self, pb_id: str, insight_context: Dict[str, Any], steps: List[Dict[str, Any]]):
        self.workflow_id = str(uuid.uuid4())
        self.pb_id = pb_id
        self.insight_context = insight_context
        self.steps = steps
        self.current_step_index = 0
        self.state = WorkflowState.PENDING
        
        # Simulating in-memory database for workflow persistence
        self.evidence_store = {}

    def start(self):
        self.state = WorkflowState.IN_PROGRESS
        logger.info(f"Started Guided Workflow {self.workflow_id} for Playbook {self.pb_id}")
        self._evaluate_current_step()

    def _evaluate_current_step(self):
        if self.current_step_index >= len(self.steps):
            self.state = WorkflowState.COMPLETED
            logger.info(f"Workflow {self.workflow_id} Completed successfully.")
            return

        current_step = self.steps[self.current_step_index]
        instruction = current_step.get("instruction")
        requires_evidence = current_step.get("requires_evidence", False)

        logger.info(f"[Workflow {self.workflow_id}] Next Step: {instruction}")
        
        if requires_evidence:
            self.state = WorkflowState.WAITING_EVIDENCE
            logger.info(f"[Workflow {self.workflow_id}] Waiting for human to provide evidence...")
        else:
            # If no evidence is required, we can automatically mark it as done or assume a UI click 'Next'
            # Here we just log and wait for an external 'advance' call
            logger.info(f"[Workflow {self.workflow_id}] Waiting for human to acknowledge step...")

    def advance(self):
        """
        Advance the workflow to the next step. Assumes the current step does not require evidence.
        """
        if self.state == WorkflowState.WAITING_EVIDENCE:
            logger.error("Cannot advance: Waiting for evidence.")
            return False
            
        self.current_step_index += 1
        self._evaluate_current_step()
        return True

    def submit_evidence(self, evidence_data: str):
        """
        Submit evidence for the current step.
        """
        if self.state != WorkflowState.WAITING_EVIDENCE:
            logger.error("Not waiting for evidence.")
            return False

        current_step = self.steps[self.current_step_index]
        step_id = current_step.get("step_id", f"step_{self.current_step_index}")
        
        # Save evidence
        self.evidence_store[step_id] = evidence_data
        logger.info(f"[Workflow {self.workflow_id}] Evidence accepted for step {step_id}.")
        
        self.state = WorkflowState.IN_PROGRESS
        self.current_step_index += 1
        self._evaluate_current_step()
        return True
