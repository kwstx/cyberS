from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Dict, Any, List
from core.models import ScanJob
from api.auth import User, RoleChecker
from api.events import publisher
from core.config import settings
import uuid

router = APIRouter(prefix="/scans", tags=["Scans"])

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "comprehensive"
    options: Dict[str, Any] = {}

# Mock DB for scan jobs
mock_scan_jobs = []

@router.post("/", response_model=ScanJob, status_code=202)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(RoleChecker(["admin", "scanner"]))
):
    """
    Trigger a new scan for a specific target. Requires 'admin' or 'scanner' role.
    """
    job_id = f"scan--{uuid.uuid4()}"
    new_job = ScanJob(
        id=job_id,
        target=request.target,
        status="pending",
        start_time=datetime.now(timezone.utc)
    )
    mock_scan_jobs.append(new_job)

    # Prepare event data to be published to Kafka orchestration topic
    event_data = {
        "event_type": "SCAN_TRIGGERED",
        "job_id": job_id,
        "target": request.target,
        "scan_type": request.scan_type,
        "options": request.options,
        "triggered_by": user.username
    }
    
    # We use fusion topic as general event bus for now, or ingestion if appropriate
    topic = settings.KAFKA_INGESTION_TOPIC 
    background_tasks.add_task(publisher.publish_event, topic, event_data)

    return new_job

@router.get("/", response_model=List[ScanJob])
async def list_scans(
    user: User = Depends(RoleChecker(["admin", "analyst", "scanner"]))
):
    """
    List all triggered scan jobs.
    """
    return mock_scan_jobs
