import logging
import uuid
from typing import Dict, Any, Optional, Set

from remediation.playbook_manager import PlaybookManager, Playbook
from remediation.policies.rl_policy import RLPolicyEngine
from remediation.actions.network_segmentation import NetworkSegmentationAction
from remediation.actions.soar_integration import SoarIntegrationAction
from remediation.actions.vendor_communication import VendorCommunicationAction
from remediation.actions.compensating_controls import CompensatingControlsAction
from remediation.workflows.guided_workflow import GuidedWorkflow

logger = logging.getLogger(__name__)

class RemediationEngine:
    def __init__(self):
        self.playbook_manager = PlaybookManager()
        self.policy_engine = RLPolicyEngine()
        
        # Register automated actions
        self.automated_actions = {
            "network_segmentation": NetworkSegmentationAction(),
            "soar_integration": SoarIntegrationAction(),
            "vendor_communication": VendorCommunicationAction(),
            "compensating_controls": CompensatingControlsAction()
        }
        
        # Keep track of active workflows
        self.active_workflows: Dict[str, GuidedWorkflow] = {}
        
        # Keep track of playbooks awaiting human/legal approval
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}

    def simulate_insight(self, insight: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulate processing an insight to evaluate its impact before execution.
        """
        logger.info(f"Simulating Insight: {insight.get('title', 'Unknown')}")
        
        eligible_playbooks = self.playbook_manager.get_eligible_playbooks(insight)
        
        if not eligible_playbooks:
            return {"status": "NO_PLAYBOOK_FOUND", "simulation_reports": []}
            
        # Select best playbook
        selected_pb = self.policy_engine.select_best_playbook(insight, eligible_playbooks)
        
        reports = []
        if selected_pb.pb_type == "automated":
            for step in selected_pb.steps:
                action_name = step.get("action")
                params = step.get("params", {})
                action_handler = self.automated_actions.get(action_name)
                
                if action_handler:
                    report = action_handler.simulate(params, insight)
                    reports.append(report)
                else:
                    reports.append({"error": f"Action '{action_name}' not implemented."})
                    
        elif selected_pb.pb_type == "guided":
            reports.append({
                "action": "Guided Workflow",
                "target": "Human Operator",
                "impact": f"Would initiate a step-by-step guided workflow requiring human interaction for playbook: {selected_pb.name}.",
                "risk_reduction": "Variable (Depends on human execution)",
                "business_disruption": "Minimal"
            })
            
        return {
            "status": "SIMULATION_SUCCESS",
            "playbook_selected": selected_pb.name,
            "simulation_reports": reports
        }

    def process_insight(self, insight: Dict[str, Any]) -> str:
        """
        Main entry point for risk insights. Determines playbook and executes it.
        Returns a status or workflow_id.
        """
        logger.info(f"Processing Insight: {insight.get('title', 'Unknown')} (Severity: {insight.get('severity')})")
        
        eligible_playbooks = self.playbook_manager.get_eligible_playbooks(insight)
        
        if not eligible_playbooks:
            logger.warning("No eligible playbooks found for insight.")
            return "NO_PLAYBOOK_FOUND"
            
        # Select best playbook using RL policy
        selected_pb = self.policy_engine.select_best_playbook(insight, eligible_playbooks)
        logger.info(f"Selected Playbook: {selected_pb.name} ({selected_pb.pb_type})")
        
        # Execute playbook
        if selected_pb.pb_type == "automated":
            if getattr(selected_pb, "requires_approval", False):
                execution_id = str(uuid.uuid4())
                roles_req = set(getattr(selected_pb, "approval_roles", []) or ["SOC_ANALYST"])
                self.pending_approvals[execution_id] = {
                    "insight": insight,
                    "playbook": selected_pb,
                    "roles_approved": set(),
                    "roles_required": roles_req
                }
                logger.info(f"Playbook {selected_pb.name} requires approval. Pending execution {execution_id}. Required roles: {roles_req}")
                return f"AWAITING_APPROVAL:{execution_id}"
                
            success = self._execute_automated_playbook(selected_pb, insight)
            # Update policy based on success
            self.policy_engine.update_policy(insight, selected_pb.pb_id, success)
            return "AUTOMATED_SUCCESS" if success else "AUTOMATED_FAILED"
            
        elif selected_pb.pb_type == "guided":
            workflow = self._start_guided_workflow(selected_pb, insight)
            return workflow.workflow_id
            
        else:
            logger.error(f"Unknown playbook type: {selected_pb.pb_type}")
            return "ERROR"

    def _execute_automated_playbook(self, playbook: Playbook, insight: Dict[str, Any]) -> bool:
        """
        Execute an automated playbook step by step.
        """
        for step in playbook.steps:
            action_name = step.get("action")
            params = step.get("params", {})
            
            action_handler = self.automated_actions.get(action_name)
            if not action_handler:
                logger.error(f"Action '{action_name}' not implemented.")
                return False
                
            success = action_handler.execute(params, insight)
            if not success:
                logger.error(f"Automated playbook failed at step: {action_name}")
                return False
                
        logger.info(f"Automated playbook {playbook.pb_id} executed successfully.")
        return True

    def _start_guided_workflow(self, playbook: Playbook, insight: Dict[str, Any]) -> GuidedWorkflow:
        workflow = GuidedWorkflow(playbook.pb_id, insight, playbook.steps)
        self.active_workflows[workflow.workflow_id] = workflow
        workflow.start()
        return workflow

    def get_workflow(self, workflow_id: str) -> Optional[GuidedWorkflow]:
        return self.active_workflows.get(workflow_id)

    def approve_action(self, execution_id: str, approver_role: str) -> str:
        """
        Authorize a pending remediation action (SOC Analyst, Legal, etc.)
        """
        if execution_id not in self.pending_approvals:
            return "NOT_FOUND"
            
        pending = self.pending_approvals[execution_id]
        if approver_role in pending["roles_required"]:
            pending["roles_approved"].add(approver_role)
            logger.info(f"Approval received from {approver_role} for execution {execution_id}.")
            
            # Check if fully approved
            if pending["roles_required"].issubset(pending["roles_approved"]):
                logger.info(f"All required approvals met for execution {execution_id}. Executing playbook.")
                success = self._execute_automated_playbook(pending["playbook"], pending["insight"])
                self.policy_engine.update_policy(pending["insight"], pending["playbook"].pb_id, success)
                del self.pending_approvals[execution_id]
                return "AUTOMATED_SUCCESS" if success else "AUTOMATED_FAILED"
            else:
                remaining = pending["roles_required"] - pending["roles_approved"]
                return f"AWAITING_FURTHER_APPROVAL (Remaining: {', '.join(remaining)})"
                
        return "INVALID_ROLE"

    def reject_action(self, execution_id: str, approver_role: str, reason: str) -> str:
        """
        Reject a pending remediation action.
        """
        if execution_id not in self.pending_approvals:
            return "NOT_FOUND"
            
        logger.warning(f"Action {execution_id} rejected by {approver_role}. Reason: {reason}")
        del self.pending_approvals[execution_id]
        return "REJECTED"
