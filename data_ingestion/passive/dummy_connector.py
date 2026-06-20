from typing import Optional
from data_ingestion.passive.base_connector import BaseAPIConnector
from data_ingestion.passive.models import IngestionResult
import time

class DummyConnector(BaseAPIConnector):
    """A dummy connector for testing the passive ingestion service."""
    async def fetch_data(self, job_id: str) -> IngestionResult:
        # In a real connector, this would be: 
        # return await self.execute_request("GET", "/some-endpoint", job_id)
        
        # Simulate network request
        await self._rate_limit()
        
        return IngestionResult(
            job_id=job_id,
            source_name=self.__class__.__name__,
            timestamp=time.time(),
            request_params={"method": "GET", "endpoint": "/dummy"},
            response_status=200,
            payload={"status": "ok", "message": "Dummy data ingested successfully."},
            errors=None
        )
