from fastapi import APIRouter, Request, HTTPException
import logging
import structlog

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
        
    logger.info("Received generic webhook", payload_keys=list(payload.keys()))
    
    # In a full implementation, we publish this payload to Kafka here
    # await publisher.publish_event("darip-raw-signals", {"source": "webhook", "data": payload})
    
    return {"status": "success", "message": "Webhook payload received and queued"}
