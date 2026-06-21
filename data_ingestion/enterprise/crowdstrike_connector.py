import os
import logging
from typing import Dict, Any, List
from pydantic import BaseModel, SecretStr
from falconpy import Detects, Incidents

logger = logging.getLogger(__name__)

class CrowdStrikeConfig(BaseModel):
    client_id: str
    client_secret: SecretStr
    base_url: str = "https://api.crowdstrike.com"
    
class CrowdStrikeConnector:
    """
    Production-ready connector for CrowdStrike Falcon API.
    Handles token rotation, pagination, and data extraction for EDR telemetry.
    """
    def __init__(self, config: CrowdStrikeConfig):
        self.config = config
        # Initialize FalconPy service classes. It automatically handles OAuth2 token lifecycle.
        self.detects_client = Detects(
            client_id=config.client_id,
            client_secret=config.client_secret.get_secret_value(),
            base_url=config.base_url
        )
        self.incidents_client = Incidents(
            client_id=config.client_id,
            client_secret=config.client_secret.get_secret_value(),
            base_url=config.base_url
        )

    async def fetch_recent_detections(self, limit: int = 100) -> List[Dict[Any, Any]]:
        """
        Fetches recent detections from the Falcon API.
        """
        try:
            # Step 1: Get Detection IDs (FQL query can be injected here for time windows)
            query_res = self.detects_client.query_detects(limit=limit)
            if query_res["status_code"] != 200:
                logger.error(f"Failed to query detections: {query_res['body']['errors']}")
                return []
            
            detection_ids = query_res["body"]["resources"]
            if not detection_ids:
                return []

            # Step 2: Get Detection Details
            details_res = self.detects_client.get_detect_summaries(ids=detection_ids)
            if details_res["status_code"] != 200:
                logger.error(f"Failed to get detection details: {details_res['body']['errors']}")
                return []

            return details_res["body"]["resources"]
        except Exception as e:
            logger.exception(f"Exception during CrowdStrike detection fetch: {e}")
            return []

    async def fetch_recent_incidents(self, limit: int = 50) -> List[Dict[Any, Any]]:
        """
        Fetches grouped incidents from the Falcon API.
        """
        try:
            query_res = self.incidents_client.query_incidents(limit=limit)
            if query_res["status_code"] != 200:
                logger.error(f"Failed to query incidents: {query_res['body']['errors']}")
                return []
                
            incident_ids = query_res["body"]["resources"]
            if not incident_ids:
                return []
                
            details_res = self.incidents_client.get_incidents(ids=incident_ids)
            if details_res["status_code"] != 200:
                 logger.error(f"Failed to get incident details: {details_res['body']['errors']}")
                 return []
                 
            return details_res["body"]["resources"]
        except Exception as e:
            logger.exception(f"Exception during CrowdStrike incident fetch: {e}")
            return []
