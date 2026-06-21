from fastapi import APIRouter, Request, HTTPException
import logging
import structlog
from api.pep import pep_engine
from api.events import publisher

logger = structlog.get_logger("api.webhooks")
router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

@router.post("/generic")
async def receive_generic_webhook(request: Request):
    """
    Generic Webhook receiver for low-code/no-code integrations.
    Payload is accepted dynamically and pushed to Kafka.
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
        
    # 1. Policy Enforcement Point (PEP) Evaluation
    await pep_engine.evaluate_inbound_webhook(request, payload)
        
    logger.info("Received generic webhook", payload_keys=list(payload.keys()))
    
    # 2. Publish payload to Kafka for ingestion/transformation
    await publisher.publish_event("darip-raw-signals", {"source": payload.get("source", "webhook"), "data": payload})
    
    return {"status": "success", "message": "Webhook payload received and queued"}
