import time
import logging
from typing import Dict, Any, Optional

from data_ingestion.passive.base_connector import BaseAPIConnector
from data_ingestion.passive.models import ConnectorConfig, IngestionResult
from core.secrets import get_secret_manager

logger = logging.getLogger("DARIP.InternalConnectors")

class InternalBaseConnector(BaseAPIConnector):
    """Base class for internal connectors that securely retrieves secrets."""
    
    def __init__(self, config: ConnectorConfig, secret_name: str):
        super().__init__(config)
        self.secret_name = secret_name
        self.secret_manager = get_secret_manager()
        
    async def _ensure_auth(self):
        """Fetches the latest API key or token from the Secret Manager."""
        if not self.config.api_key:
            token = self.secret_manager.get_secret(self.secret_name)
            if token:
                self.config.api_key = token
            else:
                logger.warning(f"Could not retrieve secret '{self.secret_name}' from secret manager.")

class SplunkConnector(InternalBaseConnector):
    """Connector for querying Splunk REST API."""
    
    def __init__(self, config: ConnectorConfig, secret_name: str = "splunk_api_token"):
        super().__init__(config, secret_name)
        
    async def fetch_data(self, job_id: str, query: str = "search index=_internal | head 100") -> IngestionResult:
        await self._ensure_auth()
        
        # Splunk typically uses Bearer tokens for REST API
        if self.config.api_key:
            self.client.headers["Authorization"] = f"Bearer {self.config.api_key}"
            
        params = {
            "search": query,
            "output_mode": "json"
        }
        
        logger.info(f"[{job_id}] Querying Splunk API: {query}")
        return await self.execute_request(
            method="POST",
            endpoint="/services/search/jobs/export",
            job_id=job_id,
            params=params
        )

class MicrosoftSentinelConnector(InternalBaseConnector):
    """Connector for querying Microsoft Sentinel / Azure Log Analytics Workspace API."""
    
    def __init__(self, config: ConnectorConfig, workspace_id: str, secret_name: str = "sentinel_oauth_token"):
        super().__init__(config, secret_name)
        self.workspace_id = workspace_id
        
    async def fetch_data(self, job_id: str, query: str = "Heartbeat | take 100") -> IngestionResult:
        await self._ensure_auth()
        
        if self.config.api_key:
            self.client.headers["Authorization"] = f"Bearer {self.config.api_key}"
            
        payload = {
            "query": query
        }
        
        endpoint = f"/v1/workspaces/{self.workspace_id}/query"
        logger.info(f"[{job_id}] Querying Microsoft Sentinel Workspace: {self.workspace_id}")
        
        return await self.execute_request(
            method="POST",
            endpoint=endpoint,
            job_id=job_id,
            json_data=payload
        )
