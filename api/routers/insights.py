from fastapi import APIRouter, Depends, Query, HTTPException
from typing import List, Optional
from core.models import Vulnerability, Exposure
from api.auth import User, RoleChecker

router = APIRouter(prefix="/insights", tags=["Insights"])

# Mock database
mock_vulnerabilities = [
    Vulnerability(id="CVE-2024-1234", name="RCE in Component X", severity="Critical", cvss_score=9.8),
]

mock_exposures = [
    Exposure(id="exposure--1", title="Open S3 Bucket", severity="High", remediation="Restrict bucket policy"),
]

@router.get("/vulnerabilities", response_model=List[Vulnerability])
async def list_vulnerabilities(
    severity: Optional[str] = None,
    user: User = Depends(RoleChecker(["admin", "analyst"]))
):
    """
    Retrieve detected vulnerabilities.
    """
    results = mock_vulnerabilities
    if severity:
        results = [v for v in results if v.severity and v.severity.lower() == severity.lower()]
    return results

@router.get("/exposures", response_model=List[Exposure])
async def list_exposures(
    severity: Optional[str] = None,
    user: User = Depends(RoleChecker(["admin", "analyst"]))
):
    """
    Retrieve detected exposures.
    """
    results = mock_exposures
    if severity:
        results = [e for e in results if e.severity and e.severity.lower() == severity.lower()]
    return results
