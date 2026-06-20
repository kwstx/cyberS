import json
import csv
from io import StringIO
from fastapi import APIRouter, Depends, HTTPException, Response
from typing import Optional
from core.models import Asset
from api.routers.assets import mock_assets
from api.auth import User, RoleChecker

router = APIRouter(prefix="/exports", tags=["Exports"])

def to_csv(data: list) -> str:
    if not data:
        return ""
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    for row in data:
        writer.writerow(row)
    return output.getvalue()

def to_stix_json(assets: list[Asset]) -> dict:
    # Extremely simplified STIX 2.1 mapping
    stix_bundle = {
        "type": "bundle",
        "id": "bundle--1234",
        "objects": []
    }
    for asset in assets:
        stix_obj = {
            "type": asset.type.value if hasattr(asset.type, 'value') else str(asset.type),
            "id": asset.id,
            "value": asset.value,
            "created": asset.created_at.isoformat(),
            "modified": asset.updated_at.isoformat()
        }
        stix_bundle["objects"].append(stix_obj)
    return stix_bundle

@router.get("/assets")
async def export_assets(
    format: str = "json",
    user: User = Depends(RoleChecker(["admin", "analyst"]))
):
    """
    Export assets in standard formats (json, csv, stix).
    """
    assets = mock_assets
    
    if format == "json":
        return [a.model_dump() for a in assets]
        
    elif format == "csv":
        data = [a.model_dump() for a in assets]
        # Flatten properties for CSV
        for d in data:
            d["properties"] = json.dumps(d.get("properties", {}))
        csv_content = to_csv(data)
        return Response(content=csv_content, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=assets.csv"})
        
    elif format == "stix":
        stix_data = to_stix_json(assets)
        return Response(content=json.dumps(stix_data), media_type="application/stix+json", headers={"Content-Disposition": "attachment; filename=assets_stix.json"})
        
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'json', 'csv', or 'stix'.")
