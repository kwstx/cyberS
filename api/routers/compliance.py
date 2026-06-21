from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

from api.auth import PermissionChecker, get_current_user, User
from governance.compliance_engine import ComplianceEngine
from governance.artifact_generator import AuditArtifactGenerator
from core.config import settings
from storage.graph import GraphRepository

router = APIRouter(prefix="/compliance", tags=["Compliance & Governance"])

# Note: GraphRepository dependencies should ideally be injected or managed via app state.
def get_graph_repo():
    return GraphRepository(
        uri=getattr(settings, "NEO4J_URI", "bolt://localhost:7687"),
        user=getattr(settings, "NEO4J_USER", "neo4j"),
        password=getattr(settings, "NEO4J_PASSWORD", "password")
    )

def get_compliance_engine(repo: GraphRepository = Depends(get_graph_repo)):
    return ComplianceEngine(graph_repo=repo)

def get_artifact_generator(repo: GraphRepository = Depends(get_graph_repo)):
    return AuditArtifactGenerator(graph_repo=repo)


class RequirementMappingRequest(BaseModel):
    requirement_text: str
    top_k: int = 3

@router.get("/status", dependencies=[Depends(PermissionChecker(action="read:reports", resource="compliance"))])
async def get_compliance_status(
    framework: str = Query(..., description="Framework to evaluate, e.g. SOC2, GDPR, ISO27001"),
    engine: ComplianceEngine = Depends(get_compliance_engine)
) -> Dict[str, Any]:
    """Get overall compliance posture against a selected framework."""
    return await engine.evaluate_graph_state(framework)

@router.post("/map-requirement", dependencies=[Depends(PermissionChecker(action="generate:reports", resource="compliance"))])
async def map_requirement(
    req: RequirementMappingRequest,
    engine: ComplianceEngine = Depends(get_compliance_engine)
) -> List[Dict[str, Any]]:
    """Use the ML engine to map a custom requirement to frameworks."""
    return engine.map_requirement_to_controls(req.requirement_text, req.top_k)

@router.get("/artifacts/{framework}", dependencies=[Depends(PermissionChecker(action="generate:reports", resource="compliance"))])
async def get_audit_artifact(
    framework: str,
    generator: AuditArtifactGenerator = Depends(get_artifact_generator)
) -> Dict[str, Any]:
    """Generate and download an audit-ready evidence package."""
    return await generator.generate_evidence_package(framework)

@router.get("/audit-logs", dependencies=[Depends(PermissionChecker(action="read:reports", resource="audit_ledger"))])
async def get_audit_logs(
    target_asset: Optional[str] = None,
    generator: AuditArtifactGenerator = Depends(get_artifact_generator)
) -> Dict[str, Any]:
    """Retrieve verifiable logs from the immutable ledger."""
    return generator.generate_chain_of_custody_log(target_asset)
