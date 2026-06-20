import logging
import base64
import httpx
import uuid
import datetime
import numpy as np
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, Any

from crypto_pqc import PQCKeyEncapsulator, secure_json_decrypt
from semantic_fusion.graph_client import GraphClient
from semantic_fusion.nlp_extractor import NLPExtractor
from semantic_fusion.gnn_resolver import GNNEntityResolver

# OpenLineage imports
from openlineage.client import OpenLineageClient, set_producer
from openlineage.client.run import RunEvent, RunState, Run
from openlineage.client.job import Job

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SemanticFusionService")

app = FastAPI(title="DARIP Semantic Fusion Service", version="2.0.0")

# Initialize clients and ML models
graph_client = GraphClient()
nlp_extractor = NLPExtractor()
gnn_resolver = GNNEntityResolver(threshold=0.85)

# OpenLineage Client
set_producer("https://github.com/kwstx/cyberS/semantic_fusion")
ol_client = OpenLineageClient(url="http://localhost:5000") # Dummy local URL for Lineage backend

# PQC KEM
pqc_kem = PQCKeyEncapsulator("Kyber768")
kem_pub, kem_priv = pqc_kem.generate_keypair()

GOVERNANCE_URL = "http://localhost:8001"

class FusionRequest(BaseModel):
    kem_ciphertext_b64: str
    encrypted_payload: str

@app.on_event("startup")
async def startup():
    await graph_client.connect()
    logger.info("Semantic Fusion initialized successfully with ML and Lineage enabled.")

@app.on_event("shutdown")
async def shutdown():
    await graph_client.close()

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/keys")
def get_keys():
    return {
        "pqc_public_key_b64": base64.b64encode(kem_pub).decode("utf-8"),
        "pqc_algorithm": pqc_kem.alg_name
    }

async def emit_lineage(run_id: str, job_name: str, state: RunState):
    """Emits an OpenLineage event."""
    try:
        event = RunEvent(
            eventType=state,
            eventTime=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            run=Run(runId=run_id),
            job=Job(namespace="darip.semantic_fusion", name=job_name),
            inputs=[],
            outputs=[]
        )
        ol_client.emit(event)
    except Exception as e:
        logger.warning(f"Failed to emit OpenLineage event: {e}")

@app.post("/fuse")
async def fuse_data(
    req: FusionRequest,
    x_darip_token: str = Header(..., alias="X-DARIP-Token"),
    x_darip_pqc_sig: str = Header(..., alias="X-DARIP-PQC-Sig")
):
    run_id = str(uuid.uuid4())
    await emit_lineage(run_id, "fuse_data_pipeline", RunState.START)
    
    try:
        # 1. Zero-Trust Check
        authz_payload = {
            "action": "inter_service_call",
            "src_service": "data_ingestion",
            "dest_service": "semantic_fusion",
            "token_str": x_darip_token,
            "pqc_token_sig": x_darip_pqc_sig
        }
        
        async with httpx.AsyncClient() as client:
            authz_resp = await client.post(f"{GOVERNANCE_URL}/authorize", json=authz_payload)
            authz_resp.raise_for_status()
            if not authz_resp.json().get("allowed"):
                raise HTTPException(status_code=403, detail="Governance Access Denied")
        
        # 2. PQC Decryption
        ciphertext = base64.b64decode(req.kem_ciphertext_b64.encode("utf-8"))
        shared_secret = pqc_kem.decapsulate(ciphertext, kem_priv)
        decrypted_data = secure_json_decrypt(req.encrypted_payload, shared_secret)

        payload = decrypted_data.get("payload", {})
        original_signal = payload.get("original_signal", {})
        enrichment = payload.get("enrichment", {})
        
        # Determine signal type
        signal_type = original_signal.get("type")
        nodes_created = 0

        # GNN Entity Resolution
        raw_entity_name = enrichment.get("normalized_entity", "Unknown")
        resolved_identity, merged = gnn_resolver.resolve_identity(raw_entity_name)

        # Base STIX Identity creation
        score = enrichment.get("darip_proprietary_score")
        await graph_client.create_identity(name=resolved_identity, security_score=score)
        nodes_created += 1

        # A. SBOM & Dependencies (SoftwareComponent)
        if signal_type == "sbom":
            pkg_name = original_signal.get("package", "unknown")
            version = original_signal.get("version", "0.0.0")
            await graph_client.add_component(
                identity_name=resolved_identity,
                name=pkg_name,
                version=version,
                source="npm/pypi_connector"
            )
            nodes_created += 1
            
        # B. Vulnerability Feed (Extract CVEs via NLP regex heuristic)
        elif signal_type == "vulnerability":
            cve_id = original_signal.get("cve_id")
            pkg = original_signal.get("package")
            if cve_id and pkg:
                # Link vulnerability (mock software link)
                await graph_client.add_component(resolved_identity, pkg, "unknown", source="vuln_feed")
                
        # C. Threat Report (Unstructured NLP Extraction)
        elif signal_type == "report":
            content = original_signal.get("content", "")
            nlp_entities = nlp_extractor.extract_entities(content)
            
            for actor in nlp_entities["ThreatActor"]:
                # Link threat actor targeting the vendor
                await graph_client.link_threat_to_identity(actor, resolved_identity, confidence=0.85)
                nodes_created += 2

        # D. Network Scanner
        elif signal_type == "network_scan":
            ip_address = original_signal.get("ip_address")
            open_ports = original_signal.get("open_ports", [])
            cves = original_signal.get("cve_detections", [])
            
            if ip_address:
                await graph_client.add_device_and_vulnerabilities(ip_address, open_ports, cves)
                nodes_created += 1

        await emit_lineage(run_id, "fuse_data_pipeline", RunState.COMPLETE)
        
        return {
            "status": "success",
            "fused_signal_type": signal_type,
            "resolved_identity": resolved_identity,
            "merged_by_gnn": merged,
            "nodes_affected": nodes_created
        }

    except HTTPException as e:
        await emit_lineage(run_id, "fuse_data_pipeline", RunState.FAIL)
        raise e
    except Exception as e:
        await emit_lineage(run_id, "fuse_data_pipeline", RunState.FAIL)
        logger.error(f"Fusion error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")


@app.get("/subgraph/{identity_name}")
async def get_vendor_subgraph(
    identity_name: str,
    x_darip_token: str = Header(..., alias="X-DARIP-Token"),
    x_darip_pqc_sig: str = Header(..., alias="X-DARIP-PQC-Sig")
):
    """
    Retrieves nth-party supply chain relationships for an identity.
    Applies Differential Privacy (Laplace noise) to aggregated security scores.
    """
    # 1. Zero Trust Check
    authz_payload = {
        "action": "read_risk_intelligence",
        "token_str": x_darip_token,
        "pqc_token_sig": x_darip_pqc_sig
    }
    try:
        async with httpx.AsyncClient() as client:
            authz_resp = await client.post(f"{GOVERNANCE_URL}/authorize", json=authz_payload)
            if not authz_resp.json().get("allowed"):
                raise HTTPException(status_code=403, detail="Unauthorized")
    except Exception:
        raise HTTPException(status_code=500, detail="Governance validation failed")

    # 2. Fetch Subgraph
    subgraph = await graph_client.get_nth_party_subgraph(identity_name, max_depth=4)
    
    # 3. Differential Privacy on aggregated analytics
    # For every Identity node returned, add Laplace noise to the security score
    epsilon = 1.0
    sensitivity = 100.0 # Score ranges from 0-100
    scale = sensitivity / epsilon

    for node in subgraph.get("nodes", []):
        if "Identity" in node.get("labels", []):
            score = node.get("properties", {}).get("security_score")
            if score is not None:
                # Add Laplace noise
                noise = np.random.laplace(0, scale)
                dp_score = max(0, min(100, score + noise))
                node["properties"]["dp_security_score"] = dp_score
                # Remove raw score to preserve privacy
                del node["properties"]["security_score"]

    return subgraph

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)

