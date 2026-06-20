from enum import Enum
from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime, timezone

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class AssetType(str, Enum):
    IP = "ipv4-addr"
    DOMAIN = "domain-name"
    CERTIFICATE = "x509-certificate"
    URL = "url"
    SOFTWARE = "software"
    ORGANIZATION = "identity"
    HOST = "host"
    CLOUD_RESOURCE = "cloud-resource"

class Asset(BaseModel):
    id: str = Field(..., description="Unique identifier for the asset (e.g., asset--<uuid>)")
    type: AssetType = Field(..., description="STIX-inspired asset type")
    value: str = Field(..., description="The main value, e.g., IP address or domain name")
    name: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    properties: Dict[str, Any] = Field(default_factory=dict, description="Additional attributes like certificate hashes, open ports, etc.")

class Vulnerability(BaseModel):
    id: str = Field(..., description="Vulnerability identifier (e.g., CVE-2024-XXXX)")
    type: Literal["vulnerability"] = "vulnerability"
    name: str = Field(..., description="Title or summary of the vulnerability")
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class Exposure(BaseModel):
    id: str = Field(..., description="Unique ID for the exposure (e.g., exposure--<uuid>)")
    type: Literal["exposure"] = "exposure"
    title: str = Field(..., description="Exposure title (e.g., 'Open S3 Bucket')")
    description: Optional[str] = None
    severity: Optional[str] = None
    remediation: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class ScanJob(BaseModel):
    id: str = Field(..., description="Scan job UUID")
    type: Literal["scan-job"] = "scan-job"
    target: str = Field(..., description="The target IP or domain of the scan")
    status: str = Field(..., description="Status: pending, running, completed, failed")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    results_summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

class RelationshipType(str, Enum):
    DEPENDS_ON = "depends_on"
    HOSTS = "hosts"
    RESOLVES_TO = "resolves_to"
    HAS_VULNERABILITY = "has_vulnerability"
    HAS_EXPOSURE = "has_exposure"
    DISCOVERED_IN = "discovered_in"

class Relationship(BaseModel):
    source_id: str = Field(..., description="ID of the source node")
    target_id: str = Field(..., description="ID of the target node")
    relationship_type: RelationshipType
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    properties: Dict[str, Any] = Field(default_factory=dict)
