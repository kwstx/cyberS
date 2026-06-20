import logging
import asyncio
import httpx
import structlog
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from core.observability import setup_observability

# Import the new LangGraph orchestrator
from agentic_execution.orchestrator import run_agentic_workflow

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
        
    # Extract data from the graph's final state
    actions_taken = []
    agent_logs = []
    
    # final_state is a dict containing the node that returned the state and the state itself.
    # We pull the 'messages' array to build the logs and actions
    if final_state:
        # The key is usually the last node that ran, but the state contains the aggregated 'messages'
        state_data = list(final_state.values())[0] 
        messages = state_data.get("messages", [])
        
        for msg in messages:
            # We skip human messages (like the initial prompt) and keep AI messages
            if msg.type == "ai":
                content = msg.content
                agent_logs.append(content)
                # Extremely rudimentary action parsing
                if "Resolved" in content or "SBOM" in content:
                    actions_taken.append("Discovery step completed.")
                if "Risk Level" in content:
                    actions_taken.append("Risk assessment performed.")
                if "mitigation plan" in content:
                    actions_taken.append("Remediation triggered.")
                if "Compliance verified" in content:
                    actions_taken.append("Compliance check passed.")

    return AgentOrchestrationResponse(
        vendor_name=vendor,
        status="completed",
        actions_taken=list(set(actions_taken)),
        agent_logs=agent_logs
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
