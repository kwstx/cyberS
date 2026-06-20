import logging
import httpx
import asyncio
import json
import os
import base64
import structlog
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from aiokafka import AIOKafkaConsumer
from tenacity import retry, wait_exponential, stop_after_attempt

from crypto_pqc import PQCKeyEncapsulator, secure_json_encrypt
from enrichment import EnrichmentPipeline
from data_ingestion.passive.service import PassiveIngestionService
from data_ingestion.passive.models import JobConfig, ConnectorConfig
from data_ingestion.passive.dummy_connector import DummyConnector
from core.observability import setup_observability

# Logging
logger = structlog.get_logger("DataIngestionService")

app = FastAPI(title="DARIP Data Ingestion Service", version="1.0.0")
setup_observability(app, "data_ingestion")

# Internal state: governance connection
GOVERNANCE_URL = os.getenv("GOVERNANCE_URL", "http://localhost:8001")
FUSION_URL = os.getenv("FUSION_URL", "http://localhost:8002")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "darip-raw-signals"

enricher = EnrichmentPipeline()

# Initialize Passive Ingestion Service
passive_service = PassiveIngestionService()
passive_service.register_connector_class("DummyConnector", DummyConnector)

# Structures for ingestion
class Component(BaseModel):
    name: str
    version: str
    purl: Optional[str] = None
    bom_ref: Optional[str] = None

class CycloneDXSBOM(BaseModel):
    bomFormat: str = "CycloneDX"
    specVersion: str
    serialNumber: str
    version: int
    metadata: Dict[str, Any]
    components: List[Component]

class ExternalRating(BaseModel):
    vendor_name: str
    security_score: int = Field(..., ge=0, le=100)
    risk_tier: str
    last_updated: str

class InternalTelemetry(BaseModel):
    device_id: str
    active_connections: int
    outbound_payload_size_mb: float
    cve_detections: List[str]

class NetworkScanResult(BaseModel):
    ip_address: str
    open_ports: List[int]
    cve_detections: List[str]

class MultiSignalPayload(BaseModel):
    sbom: Optional[CycloneDXSBOM] = None
    rating: Optional[ExternalRating] = None
    telemetry: Optional[InternalTelemetry] = None
    network_scan: Optional[NetworkScanResult] = None

# Governance Token retrieval helper
def get_governance_token() -> tuple[str, str]:
    try:
        r = httpx.post(f"{GOVERNANCE_URL}/token", json={
            "subject": "data_ingestion",
            "role": "service"
        })
        r.raise_for_status()
        data = r.json()
        return data["access_token"], data["pqc_signature"]
    except Exception as e:
        logger.error(f"Failed to fetch token from Governance Service: {e}")
        raise HTTPException(status_code=500, detail="Governance authentication failed.")

@retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3))
async def forward_to_fusion(payload: dict):
    # 1. Acquire Zero-Trust Tokens from Governance service
    try:
        token, pqc_sig = get_governance_token()
    except HTTPException as e:
        logger.error("Could not obtain governance tokens.")
        return

    # 3. Establish PQC Secure tunnel to Semantic Fusion (Simulated Kyber KEM)
    try:
        async with httpx.AsyncClient() as client:
            fusion_keys_resp = await client.get(f"{FUSION_URL}/keys")
            fusion_keys_resp.raise_for_status()
            fusion_pqc_pub_b64 = fusion_keys_resp.json()["pqc_public_key_b64"]
            fusion_pqc_pub = base64.b64decode(fusion_pqc_pub_b64.encode("utf-8"))
    except Exception as e:
        logger.error(f"Failed to retrieve public key from Fusion service: {e}")
        return

    # B. Kyber KEM
    kem = PQCKeyEncapsulator("Kyber768")
    ciphertext, shared_secret = kem.encapsulate(fusion_pqc_pub)

    # C. Encrypt the payload
    encrypted_payload_str = secure_json_encrypt(payload, shared_secret)

    # 4. Construct payload
    fusion_request = {
        "kem_ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "encrypted_payload": encrypted_payload_str
    }

    # 5. Forward encrypted data
    headers = {
        "X-DARIP-Token": token,
        "X-DARIP-PQC-Sig": pqc_sig
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{FUSION_URL}/fuse",
                json=fusion_request,
                headers=headers
            )
            resp.raise_for_status()
            logger.info("Successfully fused ingested signals in Semantic Fusion.")
    except Exception as e:
        logger.error(f"Failed to forward to Semantic Fusion: {e}")

async def consume_kafka():
    logger.info(f"Starting Kafka consumer on {KAFKA_BOOTSTRAP_SERVERS}")
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        group_id="darip-ingestion-group",
        isolation_level="read_committed" # Exactly-once semantics (read side)
    )
    
    # Retry logic for Kafka connection
    connected = False
    while not connected:
        try:
            await consumer.start()
            connected = True
            logger.info("Successfully connected to Kafka as consumer.")
        except Exception as e:
            logger.warning(f"Kafka not ready, retrying in 5s... ({e})")
            await asyncio.sleep(5)
            
    try:
        async for msg in consumer:
            logger.info(f"Received message from Kafka topic {msg.topic}")
            try:
                raw_data = json.loads(msg.value.decode('utf-8'))
                enriched_data = await enricher.enrich(raw_data)
                
                normalized_data = {
                    "source": "kafka_stream",
                    "ingested_signals": [raw_data.get("type", "unknown")],
                    "payload": enriched_data
                }
                
                await forward_to_fusion(normalized_data)
            except Exception as e:
                logger.error(f"Error processing Kafka message: {e}")
    finally:
        await consumer.stop()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(consume_kafka())
    await passive_service.start()

@app.on_event("shutdown")
async def shutdown_event():
    await passive_service.stop()

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/ingest")
async def ingest_signals(payload: MultiSignalPayload):
    logger.info("Ingestion request received. Processing signals...")
    
    normalized_data = {
        "source": "http_ingestion",
        "ingested_signals": [],
        "payload": {}
    }

    if payload.sbom:
        normalized_data["ingested_signals"].append("sbom")
        normalized_data["payload"]["sbom"] = {
            "vendor": payload.sbom.metadata.get("component", {}).get("name", "Unknown"),
            "components": [c.model_dump() for c in payload.sbom.components]
        }

    if payload.rating:
        normalized_data["ingested_signals"].append("rating")
        normalized_data["payload"]["rating"] = payload.rating.model_dump()

    if payload.telemetry:
        normalized_data["ingested_signals"].append("telemetry")
        normalized_data["payload"]["telemetry"] = payload.telemetry.model_dump()

    if payload.network_scan:
        normalized_data["ingested_signals"].append("network_scan")
        normalized_data["payload"]["network_scan"] = payload.network_scan.model_dump()

    if not normalized_data["ingested_signals"]:
        raise HTTPException(status_code=400, detail="No signals provided for ingestion.")

    # Apply synchronous enrichment conceptually, though HTTP path usually expects direct forwarding.
    # In a full system, we might push this into Kafka as well. For now, we forward directly.
    await forward_to_fusion(normalized_data)
    
    return {"status": "success", "message": "Signal queued for fusion."}

@app.post("/jobs")
async def schedule_job(job_config: JobConfig):
    try:
        passive_service.schedule_job(job_config)
        return {"status": "success", "message": f"Job {job_config.job_id} scheduled."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

