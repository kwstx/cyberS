from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from core.models import Asset, AssetType
from api.auth import User, RoleChecker

router = APIRouter(prefix="/assets", tags=["Assets"])

# Mock database for demonstration
mock_assets = [
    Asset(id="asset--1", type=AssetType.IP, value="192.168.1.100", name="Primary DB"),
    Asset(id="asset--2", type=AssetType.DOMAIN, value="api.example.com", name="API Gateway"),
]

@router.get("/", response_model=List[Asset])
async def list_assets(
    type: Optional[AssetType] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: User = Depends(RoleChecker(["admin", "analyst"]))
):
    """
    Retrieve a list of assets. Requires 'admin' or 'analyst' role.
    """
    results = mock_assets
    if type:
        results = [a for a in results if a.type == type]
    return results[offset:offset+limit]

@router.get("/{asset_id}", response_model=Asset)
async def get_asset(
    asset_id: str,
    user: User = Depends(RoleChecker(["admin", "analyst"]))
):
    """
    Retrieve a specific asset by ID.
    """
    for asset in mock_assets:
        if asset.id == asset_id:
            return asset
    raise HTTPException(status_code=404, detail="Asset not found")
