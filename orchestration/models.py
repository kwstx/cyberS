import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, time
from pydantic import BaseModel, Field

class Job(BaseModel):
    """
    Represents a task/job to be scheduled.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_domain: str
    source_ip: str
    priority: int = 10  # Lower number = higher priority
    task_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    
    # Time window constraints (UTC times)
    allowed_start_time: Optional[time] = None
    allowed_end_time: Optional[time] = None
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    scheduled_for: datetime = Field(default_factory=datetime.utcnow)
    
    # Execution history
    execution_attempts: int = 0
    last_error: Optional[str] = None
    
    def __lt__(self, other: "Job"):
        # Priority queue comparison: priority first, then scheduled_for
        if self.priority == other.priority:
            return self.scheduled_for < other.scheduled_for
        return self.priority < other.priority

class ScheduleDecision(BaseModel):
    """
    Audit log for scheduling decisions.
    """
    job_id: str
    action: str  # e.g., "executed", "delayed_rate_limit", "delayed_time_window", "delayed_ml_suggestion", "backoff"
    reason: str
    delay_seconds: float
    timestamp: datetime = Field(default_factory=datetime.utcnow)
