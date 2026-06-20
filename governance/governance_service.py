import time
import logging
import base64
import os
import structlog
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import BaseModel
from typing import Optional, Dict, Any

from crypto_pqc import PQCSigner
from core.observability import setup_observability
from core.audit import AuditEvent

# Logging
logger = structlog.get_logger("GovernanceService")

app = FastAPI(title="DARIP Governance & Zero-Trust Service", version="1.0.0")
setup_observability(app, "governance_service")
security = HTTPBearer()

# Generate asymmetric keys for standard JWT and PQC Dilithium
# Standard JWT Private Key
jwt_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
jwt_public_key = jwt_private_key.public_key()

# Serialize JWT public key to PEM
jwt_public_pem = jwt_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")

# PQC Signer
pqc_signer = PQCSigner("Dilithium3")
pqc_pub, pqc_priv = pqc_signer.generate_keypair()

# Models
class TokenRequest(BaseModel):
    subject: str        # e.g., "data_ingestion" or "discovery_agent"
    role: str           # "service" or "agent"
    agent_type: Optional[str] = None  # e.g., "discovery_agent", "remediation_agent"

class TokenResponse(BaseModel):
    access_token: str
    pqc_signature: str
    pqc_algorithm: str

class AuthzRequest(BaseModel):
    action: str                     # "inter_service_call", "agent_execution", "graph_mutation", "read_risk_intelligence"
    src_service: Optional[str] = None
    dest_service: Optional[str] = None
    agent_task: Optional[str] = None
    target_asset: Optional[str] = None
    pqc_token_sig: str
    token_str: str

class AuthzResponse(BaseModel):
    allowed: bool
    reason: str
    pqc_verified: bool

@app.get("/health")
def health():
    return {"status": "healthy", "pqc_enabled": True, "pqc_algorithm": pqc_signer.alg_name}

@app.get("/keys")
def get_public_keys():
    """Exposes public keys for token and PQC verification."""
    return {
        "jwt_public_key_pem": jwt_public_pem,
        "pqc_public_key_b64": base64.b64encode(pqc_pub).decode("utf-8"),
        "pqc_algorithm": pqc_signer.alg_name
    }

@app.post("/token", response_model=TokenResponse)
def generate_token(req: TokenRequest):
    """Issues standard JWT token and appends a Post-Quantum signature wrapper."""
    now = int(time.time())
    payload = {
        "iss": "DARIP-Governance",
        "sub": req.subject,
        "role": req.role,
        "iat": now,
        "exp": now + 3600  # 1 hour expiry
    }
    if req.agent_type:
        payload["agent_type"] = req.agent_type

    # Sign standard JWT
    token_str = jwt.encode(payload, jwt_private_key, algorithm="RS256")
    
    # Generate Post-Quantum Signature on the token string to prevent quantum interception
    pqc_sig = pqc_signer.sign(token_str.encode("utf-8"), pqc_priv)
    pqc_sig_b64 = base64.b64encode(pqc_sig).decode("utf-8")

    logger.info(f"Issued zero-trust token for {req.subject} (role: {req.role}) with PQC signature wrapper.")
    return TokenResponse(
        access_token=token_str,
        pqc_signature=pqc_sig_b64,
        pqc_algorithm=pqc_signer.alg_name
    )

def evaluate_rego_policy(input_data: Dict[str, Any]) -> tuple[bool, str]:
    """
    Python-based high-fidelity implementation of the policies.rego rules.
    This parses the policy inputs and evaluates claims against the same constraints.
    """
    action = input_data.get("action")
    claims = input_data.get("token", {}).get("claims", {})
    target = input_data.get("target_asset")
    
    # Allow-list Policy Enforcement
    allow_list_str = os.getenv("APPROVED_ASSET_ALLOWLIST", "")
    if allow_list_str:
        allow_list = [a.strip() for a in allow_list_str.split(",") if a.strip()]
        if action == "agent_execution" and target:
            if target not in allow_list:
                return False, f"Target asset {target} is not in the approved allow-list."

    # Verify Issuer
    if claims.get("iss") != "DARIP-Governance":
        return False, "Invalid issuer claim."
        
    sub = claims.get("sub")
    role = claims.get("role")
    
    if action == "inter_service_call":
        src = input_data.get("src_service")
        dest = input_data.get("dest_service")
        
        # Ingestion -> Fusion
        if src == "data_ingestion" and dest == "semantic_fusion":
            return True, "Valid inter-service data flow."
        # Fusion -> Graph
        if src == "semantic_fusion" and dest == "stateful_graph":
            return True, "Valid database write flow."
        # Inference -> Graph
        if src == "predictive_inference" and dest == "stateful_graph":
            return True, "Valid database read flow."
        # Agent -> Inference
        if src == "agentic_execution" and dest == "predictive_inference":
            return True, "Valid inference query flow."
        # Agent -> Fusion
        if src == "agentic_execution" and dest == "semantic_fusion":
            return True, "Valid telemetry flow."
        # Governance admin
        if src == "governance":
            return True, "Governance override."
            
        return False, f"Unauthorized service-to-service flow: {src} -> {dest}"
        
    elif action == "agent_execution":
        if role != "agent":
            return False, "Caller role is not an agent."
        agent_type = claims.get("agent_type")
        task = input_data.get("agent_task")
        
        # Discovery agent capabilities
        if agent_type == "discovery_agent":
            if task in ["discover_vendor", "read_sbom"]:
                return True, "Authorized task for discovery agent."
            return False, f"Discovery Agent unauthorized for task: {task}"
            
        # Risk evaluator capabilities
        if agent_type == "risk_evaluator_agent":
            if task in ["query_subgraph", "predict_risk"]:
                return True, "Authorized task for risk evaluator."
            return False, f"Risk Evaluator unauthorized for task: {task}"
            
        # Remediation agent capabilities
        if agent_type == "remediation_agent":
            if task in ["trigger_remediation", "verify_remediation"]:
                return True, "Authorized task for remediation agent."
            return False, f"Remediation Agent unauthorized for task: {task}"
            
        return False, f"Unknown agent type: {agent_type}"
        
    elif action == "graph_mutation":
        if sub in ["semantic_fusion", "governance"]:
            return True, "Service authorized to mutate graph state."
        return False, f"Service {sub} cannot write to graph."
        
    elif action == "read_risk_intelligence":
        if sub in ["predictive_inference", "agentic_execution", "governance"]:
            return True, "Service authorized to read risk intelligence."
        return False, f"Service {sub} cannot read risk intelligence."
        
    return False, f"Unknown action: {action}"

@app.post("/authorize", response_model=AuthzResponse)
def authorize_action(req: AuthzRequest):
    """
    Validates token, verifies PQC signature, and evaluates the authorization
    policy in real time (Zero-Trust enforcement point).
    """
    # 1. Decode and verify standard JWT token
    try:
        claims = jwt.decode(req.token_str, jwt_public_key, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired.")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
        
    # 2. Verify Post-Quantum Cryptographic Signature
    pqc_sig = base64.b64decode(req.pqc_token_sig.encode("utf-8"))
    pqc_verified = pqc_signer.verify(req.token_str.encode("utf-8"), pqc_sig, pqc_pub)
    
    if not pqc_verified:
        logger.warning(f"PQC verification failed for token issued to {claims.get('sub')}.")
        return AuthzResponse(
            allowed=False,
            reason="Post-quantum signature verification failed.",
            pqc_verified=False
        )

    # 3. Evaluate Policy-as-Code (Rego rules)
    input_data = {
        "action": req.action,
        "src_service": req.src_service,
        "dest_service": req.dest_service,
        "agent_task": req.agent_task,
        "target_asset": req.target_asset,
        "token": {
            "claims": claims
        }
    }
    
    allowed, reason = evaluate_rego_policy(input_data)
    logger.info(f"Authz evaluation: Action='{req.action}', Sub='{claims.get('sub')}', Allowed={allowed}, PQC_Verified={pqc_verified}")
    
    AuditEvent.log(
        action=req.action,
        actor=claims.get("sub", "unknown"),
        target=req.target_asset or req.dest_service or "system",
        status="ALLOWED" if allowed else "DENIED",
        details={"reason": reason, "pqc_verified": pqc_verified, "agent_task": req.agent_task}
    )
    
    return AuthzResponse(
        allowed=allowed,
        reason=reason,
        pqc_verified=pqc_verified
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
