import logging
from typing import Dict, Any, List
from fastapi import Request, HTTPException

logger = logging.getLogger("api.pep")

class PolicyEnforcementPoint:
    """
    Natively evaluates zero-trust policies for outbound automations and inbound data.
    In a full production environment, this could forward requests to Open Policy Agent (OPA).
    """
    
    def __init__(self):
        # Mock policy rules (JSON format natively evaluated)
        self.policies = {
            "allow_automated_vendor_blocking": True,
            "require_human_in_loop_for_severity": ["critical"],
            "allowed_webhook_sources": ["servicenow", "ariba", "custom_hr_system"]
        }

    def evaluate_outbound_action(self, action_type: str, severity: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate if an outbound action (like blocking a vendor) is permitted without human intervention.
        """
        logger.info(f"[PEP] Evaluating outbound action: {action_type} (Severity: {severity})")
        
        if action_type == "block_vendor":
            if not self.policies["allow_automated_vendor_blocking"]:
                logger.warning("[PEP] DENY: Automated vendor blocking is disabled globally.")
                return False
            
            if severity.lower() in self.policies["require_human_in_loop_for_severity"]:
                # E.g. A 'critical' severity action might require a human to approve in ServiceNow first
                logger.warning(f"[PEP] DENY: {severity} severity requires human-in-the-loop approval.")
                return False
                
            logger.info("[PEP] PERMIT: Action allowed by policy.")
            return True
            
        return False

    async def evaluate_inbound_webhook(self, request: Request, payload: Dict[str, Any]) -> bool:
        """
        Evaluate if an incoming webhook is from a permitted source and fits the schema.
        Could be used as a FastAPI Dependency.
        """
        source = payload.get("source")
        if source not in self.policies["allowed_webhook_sources"]:
            logger.warning(f"[PEP] DENY: Webhook source '{source}' is not in allowed list.")
            raise HTTPException(status_code=403, detail="Policy Enforcement: Source not allowed.")
            
        logger.info(f"[PEP] PERMIT: Inbound webhook from {source} allowed.")
        return True

pep_engine = PolicyEnforcementPoint()
