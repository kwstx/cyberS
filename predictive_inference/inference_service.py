import logging
import httpx
import structlog
import torch
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, List, Any
from core.observability import setup_observability
from core.audit import AuditEvent
from predictive_inference.models.multi_modal import MultiModalFusionEngine
from predictive_inference.causal_inference import SupplyChainSCM
from predictive_inference.explainer import ExplainerService
import networkx as nx

# Logging
logger = structlog.get_logger("PredictiveInferenceService")

# Initialize Engine
try:
    fusion_engine = MultiModalFusionEngine()
    fusion_engine.eval()
except Exception as e:
    logger.error(f"Failed to initialize MultiModalFusionEngine: {e}")
    fusion_engine = None

explainer_service = ExplainerService()

app = FastAPI(title="DARIP Predictive Inference Service", version="1.0.0")
setup_observability(app, "predictive_inference")

GOVERNANCE_URL = "http://localhost:8001"
FUSION_URL = "http://localhost:8002"

class PredictionRequest(BaseModel):
    vendor_name: str

class PredictionResponse(BaseModel):
    vendor_name: str
    composite_risk_score: float
    risk_level: str
    vulnerability_cascade_probability: float
    nth_party_affected_count: int
    contributing_factors: List[str]
    confidence_interval_95_risk: List[float] = [0.0, 0.0]
    shap_values: Dict[str, float] = {}

class InterventionRequest(BaseModel):
    vendor_name: str
    target_vendor: str
    intervention_vendor: str

class InterventionResponse(BaseModel):
    target_vendor: str
    intervention_vendor: str
    causal_effect: float

# Fetch token from Governance
def get_governance_token() -> tuple[str, str]:
    try:
        r = httpx.post(f"{GOVERNANCE_URL}/token", json={
            "subject": "predictive_inference",
            "role": "service"
        })
        r.raise_for_status()
        data = r.json()
        return data["access_token"], data["pqc_signature"]
    except Exception as e:
        logger.error(f"Failed to fetch token: {e}")
        raise HTTPException(status_code=500, detail="Governance authentication failed.")

@app.get("/health")
def health():
    return {"status": "healthy"}
# In-memory cache for graceful degradation fallbacks
subgraph_cache = {}

@app.post("/predict", response_model=PredictionResponse)
async def predict_vendor_risk(req: PredictionRequest):
    """
    Decoupled stateless inference node.
    1. Fetches stateful subgraph for the vendor from Semantic Fusion.
    2. Simulates graph neural network / probabilistic risk calculations on the subgraph structure.
    3. Outputs risk score, level, and cascade likelihood.
    """
    logger.info(f"Received risk prediction request for vendor '{req.vendor_name}'")
    
    is_degraded = False
    headers = {}
    
    # 1. Fetch Auth credentials
    try:
        token, pqc_sig = get_governance_token()
        headers = {
            "X-DARIP-Token": token,
            "X-DARIP-PQC-Sig": pqc_sig
        }
    except Exception as e:
        logger.warning(f"Could not obtain governance token: {e}. Operating in degraded mode.")
        is_degraded = True

    # 2. Fetch Subgraph from stateful Fusion storage
    subgraph = None
    if not is_degraded:
        try:
            async with httpx.AsyncClient() as client:
                subgraph_resp = await client.get(
                    f"{FUSION_URL}/subgraph/{req.vendor_name}",
                    headers=headers
                )
                subgraph_resp.raise_for_status()
                subgraph = subgraph_resp.json()
                # Store in cache
                subgraph_cache[req.vendor_name] = subgraph
        except Exception as e:
            logger.warning(f"Failed to retrieve subgraph for {req.vendor_name}: {e}. Operating in degraded mode.")
            is_degraded = True

    if is_degraded or subgraph is None:
        # Graceful fallback: check cache
        subgraph = subgraph_cache.get(req.vendor_name)
        if subgraph is None:
            logger.info(f"No cached subgraph for '{req.vendor_name}'. Using baseline default.")
            # Build baseline default subgraph
            subgraph = {
                "nodes": [
                    {
                        "labels": ["Vendor"],
                        "properties": {
                            "name": req.vendor_name,
                            "security_score": 75
                        }
                    }
                ],
                "edges": []
            }
        else:
            logger.info(f"Retrieved cached subgraph for '{req.vendor_name}'")

    # 3. Process predictive risk algorithm (Stateless Inference)
    nodes = subgraph.get("nodes", [])
    edges = subgraph.get("edges", [])
    
    # Count of components, devices, and vendor links
    vendor_count = 0
    component_count = 0
    device_count = 0
    total_rating_score = 0
    active_cves_count = 0
    
    factors = []
    
    for node in nodes:
        labels = node.get("labels", [])
        props = node.get("properties", {})
        if "Vendor" in labels:
            vendor_count += 1
            if props.get("security_score"):
                total_rating_score += props.get("security_score")
        elif "Component" in labels:
            component_count += 1
        elif "Device" in labels:
            device_count += 1
            
    for edge in edges:
        props = edge.get("properties", {})
        if props.get("cves"):
            active_cves_count += len(props.get("cves"))

    # Calculate average vendor security rating in subgraph (defaulting to 80 if none)
    avg_vendor_rating = (total_rating_score / vendor_count) if vendor_count > 0 else 80.0
    
    # Prepare features for Multi-Modal Engine
    num_nodes = len(nodes)
    node_features = torch.zeros((num_nodes, 5))
    if num_nodes > 0:
        node_features[:, 0] = avg_vendor_rating / 100.0
        node_features[:, 1] = active_cves_count / 10.0
    
    edge_index = torch.zeros((2, max(1, len(edges))), dtype=torch.long)
    
    text_data = [f"Threat intelligence summary for {req.vendor_name}"]
    if active_cves_count > 0:
         text_data.append(f"Detected {active_cves_count} active vulnerabilities in upstream dependencies.")
         
    time_series = torch.rand((1, 30, 3)) # Mock 30 days of historical telemetry
    
    if fusion_engine is not None:
        mc_preds = fusion_engine.mc_forward(node_features, edge_index, text_data, time_series, num_samples=10)
        base_risk = mc_preds["composite_risk_score_mean"]
        cascade_prob = mc_preds["vulnerability_cascade_probability_mean"]
        ci_risk = mc_preds["confidence_interval_95_risk"]
    else:
        # Fallback heuristics
        cascade_prob = 0.05 + (0.05 * min(vendor_count, 8)) + (0.15 * min(active_cves_count, 4))
        cascade_prob = min(cascade_prob, 0.99)
        base_risk = (100.0 - avg_vendor_rating) * 0.4 + (active_cves_count * 15.0) + (vendor_count * 4.0)
        base_risk = max(5.0, min(base_risk, 95.0))
        ci_risk = [max(0.0, base_risk - 15.0), min(100.0, base_risk + 15.0)]
        factors.append("Multi-modal engine unavailable. Using fallback heuristics.")
    
    # Formulate contributing factors
    if is_degraded:
        factors.append("Operating in degraded mode: external dependencies offline. Baseline/cached data applied.")
    if avg_vendor_rating < 70:
        factors.append(f"Low average ecosystem security rating: {avg_vendor_rating:.1f}")
    if active_cves_count > 0:
        factors.append(f"{active_cves_count} active vulnerabilities detected in downstream packages")
    if vendor_count > 2:
        factors.append(f"Deep multi-tier dependency chain detected ({vendor_count} vendors deep)")
    if cascade_prob > 0.4:
        factors.append(f"High vulnerability propagation probability ({cascade_prob*100:.1f}%) due to shared libraries")
        
    if not factors:
        factors.append("No critical risk indicators detected. Baseline ecosystem healthy.")

    # Determine risk level
    if base_risk >= 75:
        risk_level = "CRITICAL"
    elif base_risk >= 50:
        risk_level = "HIGH"
    elif base_risk >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    logger.info(f"Prediction computed: RiskScore={base_risk:.2f}, CascadeProb={cascade_prob:.2f}, Degraded={is_degraded}")

    # Compute SHAP Values
    shap_vals = explainer_service.explain_prediction(avg_vendor_rating, active_cves_count, vendor_count)

    # Full Provenance Tracking
    AuditEvent.log(
        action="risk_assessment_generated",
        actor="predictive_inference",
        target=req.vendor_name,
        status="SUCCESS",
        details={
            "model_version": "Heuristic_Fallback" if is_degraded or fusion_engine is None else "MultiModal_v1",
            "input_features": {
                "avg_vendor_rating": avg_vendor_rating,
                "active_cves_count": active_cves_count,
                "vendor_count": vendor_count
            },
            "shap_values": shap_vals,
            "final_score": round(base_risk, 2),
            "risk_level": risk_level
        }
    )

    return PredictionResponse(
        vendor_name=req.vendor_name,
        composite_risk_score=round(base_risk, 2),
        risk_level=risk_level,
        vulnerability_cascade_probability=round(cascade_prob, 3),
        nth_party_affected_count=max(0, vendor_count - 1),
        contributing_factors=factors,
        confidence_interval_95_risk=[round(x, 2) for x in ci_risk],
        shap_values=shap_vals
    )

@app.post("/predict/intervention", response_model=InterventionResponse)
async def predict_intervention(req: InterventionRequest):
    """
    Do-calculus what-if scenario endpoint.
    Retrieves the subgraph, builds an nx.DiGraph, and measures the Causal Effect
    of an intervention (e.g., intervention_vendor being compromised) on the target_vendor.
    """
    # For demonstration, we build a dummy DAG simulating the dependency chain
    G = nx.DiGraph()
    G.add_node(req.intervention_vendor, active_cves=["CVE-FAKE"])
    G.add_node(req.target_vendor, active_cves=[])
    G.add_edge(req.intervention_vendor, req.target_vendor, weight=1.0)
    
    scm = SupplyChainSCM()
    effect = scm.estimate_causal_effect(G, req.target_vendor, req.intervention_vendor)
    
    return InterventionResponse(
        target_vendor=req.target_vendor,
        intervention_vendor=req.intervention_vendor,
        causal_effect=round(effect, 4)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
