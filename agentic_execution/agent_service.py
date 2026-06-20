import logging
import asyncio
import httpx
import structlog
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from core.observability import setup_observability

# Import the new LangGraph orchestrator
from agentic_execution.orchestrator import run_agentic_workflow, approve_workflow
from agentic_execution.memory import audit_logger

# Logging
logger = structlog.get_logger("AgenticExecutionService")

app = FastAPI(title="DARIP Agentic Execution Service", version="1.0.0")
setup_observability(app, "agentic_execution")

class AgentOrchestrationRequest(BaseModel):
    vendor_name: str

class AgentOrchestrationResponse(BaseModel):
    vendor_name: str
    status: str
    actions_taken: List[str]
    agent_logs: List[str]
    audit_trail: List[Dict[str, Any]]

class AgentApprovalRequest(BaseModel):
    vendor_name: str
    approved: bool

@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/orchestrate", response_model=AgentOrchestrationResponse)
async def orchestrate_agents(req: AgentOrchestrationRequest):
    """
    Triggers a multi-agent evaluation workflow utilizing LangGraph.
    - Supervisor: Plans and decomposes the workflow.
    - Compliance Agent: Verifies policy permissions.
    - Discovery Agent: Maps supply chain details and checks SBOM signals.
    - Assessment Agent: Performs risk inference, checking cascade thresholds.
    - Remediation Agent: Deploys auto-mitigation strategies if threats are detected.
    """
    vendor = req.vendor_name
    logger.info(f"Initiating LangGraph agentic workflow for supply chain: {vendor}")
    
    # Run the graph
    try:
        # In a fully async application, run_agentic_workflow should be awaited or wrapped in run_in_executor
        # Here we assume a fast synchronous execution for the mock demo
        final_state = run_agentic_workflow(vendor)
    except Exception as e:
        logger.error(f"Failed to execute agentic workflow: {e}")
        raise HTTPException(status_code=500, detail="Workflow execution failed.")
        
    # Extract data from the graph's final state or current state if interrupted
    actions_taken = []
    agent_logs = []
    
    # We check if it returned the dict with 'status'
    status = "completed"
    if isinstance(final_state, dict) and "status" in final_state:
        status = final_state["status"]
        state_data = final_state.get("state", {})
    else:
        state_data = final_state

    if state_data:
        messages = state_data.get("messages", [])
        for msg in messages:
            if msg.type == "ai":
                content = msg.content
                agent_logs.append(content)
                if "Resolved" in content or "SBOM" in content:
                    actions_taken.append("Discovery step completed.")
                if "Risk Level" in content:
                    actions_taken.append("Risk assessment performed.")
                if "mitigation plan" in content:
                    actions_taken.append("Remediation triggered.")
                if "Compliance verified" in content:
                    actions_taken.append("Compliance check passed.")

    audit_trail = audit_logger.get_trail(vendor)

    return AgentOrchestrationResponse(
        vendor_name=vendor,
        status=status,
        actions_taken=list(set(actions_taken)),
        agent_logs=agent_logs,
        audit_trail=audit_trail
    )

@app.post("/approve", response_model=AgentOrchestrationResponse)
async def approve_agent_workflow(req: AgentApprovalRequest):
    """
    Resumes a paused workflow after a human reviews the uncertainty.
    """
    vendor = req.vendor_name
    
    if req.approved:
        audit_logger.log_action(vendor, "HumanOperator", "approved_workflow")
        try:
            final_state = approve_workflow(vendor)
        except Exception as e:
            logger.error(f"Failed to resume workflow: {e}")
            raise HTTPException(status_code=500, detail="Workflow resume failed.")
    else:
        audit_logger.log_action(vendor, "HumanOperator", "rejected_workflow")
        # For rejection, we would ideally update the state to cancel or finish.
        # For this demo, we'll just log and return.
        final_state = {"status": "rejected_by_human"}
        
    audit_trail = audit_logger.get_trail(vendor)
    
    return AgentOrchestrationResponse(
        vendor_name=vendor,
        status="completed" if req.approved else "rejected",
        actions_taken=["Human Approval processed"],
        agent_logs=[],
        audit_trail=audit_trail
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
