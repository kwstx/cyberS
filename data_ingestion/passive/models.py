from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

class ConnectorConfig(BaseModel):
    """Configuration for a passive API connector."""
    base_url: str = Field(..., description="Base URL of the external API.")
    timeout: float = Field(10.0, description="Request timeout in seconds.")
    api_key: Optional[str] = Field(None, description="API key or token for authorization.")
    rate_limit_rps: float = Field(1.0, description="Rate limit in requests per second.")
    max_retries: int = Field(3, description="Maximum number of retries for failed requests.")
    extra_headers: Dict[str, str] = Field(default_factory=dict, description="Additional headers to include in requests.")

class JobConfig(BaseModel):
    """Configuration for an ingestion job schedule."""
    job_id: str = Field(..., description="Unique identifier for the job.")
    connector_class: str = Field(..., description="Name of the connector class to instantiate.")
    cron_schedule: Optional[str] = Field(None, description="Cron expression for scheduling (e.g., '0 * * * *').")
    interval_seconds: Optional[int] = Field(None, description="Interval in seconds for scheduling.")
    connector_config: ConnectorConfig = Field(..., description="Configuration passed to the connector.")

class IngestionResult(BaseModel):
    """Structured logging and provenance result of an ingestion execution."""
    job_id: str
    source_name: str
    timestamp: float
    request_params: Dict[str, Any]
    response_status: Optional[int]
    payload: Optional[Dict[str, Any]]
    errors: Optional[str]
