import json
import logging
from typing import Dict, Any, List

from core.models import Asset, AssetType, utc_now

logger = logging.getLogger("DARIP.InternalNormalizer")

class TelemetryNormalizer:
    """Normalizes raw internal telemetry into DARIP Asset models."""

    @staticmethod
    def normalize_splunk_host(raw_data: Dict[str, Any]) -> Asset:
        """
        Maps a Splunk host inventory record to an Asset.
        Expected raw_data fields: host, ip, os, mac, etc.
        """
        hostname = raw_data.get("host", "unknown-host")
        ip_addr = raw_data.get("ip")
        
        # Primary identifier is host, fallback to IP
        asset_id = f"asset--splunk--{hostname}"
        
        properties = {
            "source": "splunk",
            "os": raw_data.get("os"),
            "mac": raw_data.get("mac"),
            "raw_payload": raw_data
        }
        if ip_addr:
            properties["ip_address"] = ip_addr

        return Asset(
            id=asset_id,
            type=AssetType.HOST,
            value=hostname,
            name=f"Splunk Host: {hostname}",
            properties=properties
        )

    @staticmethod
    def normalize_sentinel_resource(raw_data: Dict[str, Any]) -> Asset:
        """
        Maps a Microsoft Sentinel / Azure resource to an Asset.
        Expected raw_data fields: ResourceId, Name, Type, Location.
        """
        resource_id = raw_data.get("ResourceId", "unknown-resource")
        name = raw_data.get("Name", "Unknown Azure Resource")
        
        asset_id = f"asset--sentinel--{resource_id.replace('/', '-')}"
        
        properties = {
            "source": "microsoft_sentinel",
            "azure_type": raw_data.get("Type"),
            "location": raw_data.get("Location"),
            "raw_payload": raw_data
        }

        return Asset(
            id=asset_id,
            type=AssetType.CLOUD_RESOURCE,
            value=resource_id,
            name=f"Azure Resource: {name}",
            properties=properties
        )

    @classmethod
    def process_splunk_results(cls, results: List[Dict[str, Any]]) -> List[Asset]:
        return [cls.normalize_splunk_host(res) for res in results]

    @classmethod
    def process_sentinel_results(cls, results: List[Dict[str, Any]]) -> List[Asset]:
        return [cls.normalize_sentinel_resource(res) for res in results]
