import logging
import asyncio
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AgenticExecutionService")

app = FastAPI(title="DARIP Agentic Execution Service", version="1.0.0")

GOVERNANCE_URL = "http://localhost:8001"
FUSION_URL = "http://localhost:8002"
INFERENCE_URL = "http://localhost:8003"

class AgentOrchestrationRequest(BaseModel):
    vendor_name: str

class AgentOrchestrationResponse(BaseModel):
    vendor_name: str
    status: str
    discovery_agent_log: str
    evaluator_agent_log: str
    remediation_agent_log: str
    actions_taken: List[str]

# Helper: Retrieve agent-specific token from Governance
def get_agent_token(agent_type: str) -> tuple[str, str]:
    try:
        r = httpx.post(f"{GOVERNANCE_URL}/token", json={
            "subject": f"{agent_type}_worker",
            "role": "agent",
            "agent_type": agent_type
        })
        r.raise_for_status()
        data = r.json()
        return data["access_token"], data["pqc_signature"]
    except Exception as e:
        logger.error(f"Failed to fetch agent token for {agent_type}: {e}")
        raise HTTPException(status_code=500, detail=f"Agent {agent_type} authentication failed.")

# Helper: Check if Governance OPA policy authorizes this agent action
async def verify_agent_action(agent_type: str, action: str, token_str: str, pqc_sig: str) -> bool:
    payload = {
        "action": "agent_execution",
        "agent_task": action,
        "token_str": token_str,
        "pqc_token_sig": pqc_sig
    }
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{GOVERNANCE_URL}/authorize", json=payload)
            resp.raise_for_status()
            return resp.json().get("allowed", False)
    except Exception as e:
        logger.error(f"Error querying authorization for {agent_type}: {e}")
        return False

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/orchestrate", response_model=AgentOrchestrationResponse)
async def orchestrate_agents(req: AgentOrchestrationRequest):
    """
    Triggers a multi-agent evaluation workflow.
    - Discovery Agent: Maps supply chain details and checks SBOM signals.
    - Risk Evaluator Agent: Performs risk inference, checking cascade thresholds.
    - Remediation Agent: Deploys auto-mitigation strategies if threats are detected.
    Each step performs real-time Governance authorization.
    """
    vendor = req.vendor_name
    logger.info(f"Initiating agentic workflow for supply chain: {vendor}")
    
    actions_taken = []
    
    # ----------------------------------------------------
    # 1. DISCOVERY AGENT ACTIVATION
    # ----------------------------------------------------
    disc_type = "discovery_agent"
    disc_token, disc_pqc = get_agent_token(disc_type)
    
    # Action A: Read SBOM
    disc_authorized = await verify_agent_action(disc_type, "read_sbom", disc_token, disc_pqc)
    if not disc_authorized:
        logger.error(f"Discovery Agent failed policy check for 'read_sbom'.")
        raise HTTPException(status_code=403, detail="Discovery Agent unauthorized for read_sbom.")
    
    disc_log = f"[{disc_type}] Policy authorized 'read_sbom'. Mapping components in root vendor '{vendor}'... "
    # Simulate scanning components
    await asyncio.sleep(0.5) 
    disc_log += "Resolved 1 primary software dependency: OpenSSL 1.1.1t. "
    
    # Action B: Discover Vendor dependencies
    disc_authorized_2 = await verify_agent_action(disc_type, "discover_vendor", disc_token, disc_pqc)
    if not disc_authorized_2:
        logger.error(f"Discovery Agent failed policy check for 'discover_vendor'.")
        raise HTTPException(status_code=403, detail="Discovery Agent unauthorized for discover_vendor.")
        
    disc_log += f"Polled public intelligence. Verified 4th-party suppliers for '{vendor}'."
    actions_taken.append("Discovered software components and sub-tier supply relationships")

    # ----------------------------------------------------
    # 2. RISK EVALUATOR AGENT ACTIVATION
    # ----------------------------------------------------
    eval_type = "risk_evaluator_agent"
    eval_token, eval_pqc = get_agent_token(eval_type)
    
    # Action A: Query Subgraph Risk
    eval_authorized = await verify_agent_action(eval_type, "query_subgraph", eval_token, eval_pqc)
    if not eval_authorized:
        logger.error(f"Risk Evaluator Agent failed policy check for 'query_subgraph'.")
        raise HTTPException(status_code=403, detail="Risk Evaluator Agent unauthorized for query_subgraph.")

    eval_log = f"[{eval_type}] Policy authorized 'query_subgraph'. Querying predictive risk intelligence service... "
    
    # Invoke predictive inference service
    try:
        async with httpx.AsyncClient() as client:
            pred_resp = await client.post(
                f"{INFERENCE_URL}/predict",
                json={"vendor_name": vendor}
            )
            pred_resp.raise_for_status()
            risk_predictions = pred_resp.json()
    except Exception as e:
        logger.error(f"Predictive inference call failed: {e}")
        raise HTTPException(status_code=502, detail="Failed to run predictive inference on the vendor.")
        
    score = risk_predictions.get("composite_risk_score", 0.0)
    level = risk_predictions.get("risk_level", "LOW")
    cascade_prob = risk_predictions.get("vulnerability_cascade_probability", 0.0)
    
    eval_log += f"Received prediction: Risk Index={score} ({level}), Cascade Likelihood={cascade_prob*100:.1f}%. "
    
    # Action B: Decide if risk is acceptable
    eval_log += "Analyzing risk footprint. "
    needs_remediation = False
    if level in ["HIGH", "CRITICAL"]:
        eval_log += f"ALERT: Ecosystem threat level is '{level}' which exceeds threshold. Handing off to Remediation Agent."
        needs_remediation = True
    else:
        eval_log += "Ecosystem risk is within acceptable thresholds. No immediate action required."
        
    actions_taken.append(f"Evaluated risk: Score={score}, Level={level}")

    # ----------------------------------------------------
    # 3. REMEDIATION AGENT ACTIVATION
    # ----------------------------------------------------
    rem_type = "remediation_agent"
    rem_token, rem_pqc = get_agent_token(rem_type)
    
    if needs_remediation:
        # Action A: Trigger Remediation
        rem_authorized = await verify_agent_action(rem_type, "trigger_remediation", rem_token, rem_pqc)
        if not rem_authorized:
            logger.error(f"Remediation Agent failed policy check for 'trigger_remediation'.")
            raise HTTPException(status_code=403, detail="Remediation Agent unauthorized for trigger_remediation.")
            
        rem_log = f"[{rem_type}] Policy authorized 'trigger_remediation'. Executing automated risk mitigation... "
        # Simulate remediation strategy (e.g. recommending version patch or quarantine)
        await asyncio.sleep(0.5)
        rem_log += f"Generated mitigation plan: Patch OpenSSL 1.1.1t to OpenSSL 3.0.x (mitigates CVE-2023-0286). Sent notification alert to Cyber Security Operations (SecOps)."
        actions_taken.append("Triggered automated dependency patch recommendation")
        
        # Action B: Verify Remediation status
        rem_authorized_2 = await verify_agent_action(rem_type, "verify_remediation", rem_token, rem_pqc)
        if rem_authorized_2:
            rem_log += " Initiated validation checks for replacement build."
    else:
        # If no remediation is needed, logging is minimal but the agent still monitors
        rem_log = f"[{rem_type}] Idle. Ecosystem verified safe."
        
    return AgentOrchestrationResponse(
        vendor_name=vendor,
        status="completed" if not needs_remediation else "remediation_triggered",
        discovery_agent_log=disc_log,
        evaluator_agent_log=eval_log,
        remediation_agent_log=rem_log,
        actions_taken=actions_taken
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
