import strawberry
from typing import List, Optional
from core.models import AssetType
from datetime import datetime

# Convert Enum for Strawberry
@strawberry.enum
class GQLAssetType(strawberry.Enum):
    IP = "ipv4-addr"
    DOMAIN = "domain-name"
    CERTIFICATE = "x509-certificate"
    URL = "url"
    SOFTWARE = "software"
    ORGANIZATION = "identity"
    HOST = "host"
    CLOUD_RESOURCE = "cloud-resource"

@strawberry.type
class Asset:
    id: str
    type: GQLAssetType
    value: str
    name: Optional[str]
    created_at: datetime
    updated_at: datetime
    # properties is omitted or we could use a custom scalar/JSON

from api.routers.assets import mock_assets

@strawberry.type
class Query:
    @strawberry.field
    def assets(self, limit: int = 50, offset: int = 0) -> List[Asset]:
        results = []
        for a in mock_assets[offset:offset+limit]:
            results.append(Asset(
                id=a.id,
                type=GQLAssetType(a.type.value),
                value=a.value,
                name=a.name,
                created_at=a.created_at,
                updated_at=a.updated_at
            ))
        return results

    @strawberry.field
    def asset(self, id: str) -> Optional[Asset]:
        for a in mock_assets:
            if a.id == id:
                return Asset(
                    id=a.id,
                    type=GQLAssetType(a.type.value),
                    value=a.value,
                    name=a.name,
                    created_at=a.created_at,
                    updated_at=a.updated_at
                )
        return None

schema = strawberry.Schema(query=Query)
