import aiohttp
import logging
from typing import Dict, Any

logger = logging.getLogger("connectors.splunk")

class SplunkHECConnector:
    def __init__(self, hec_url: str, hec_token: str):
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        }

    async def send_event(self, event_data: Dict[str, Any], sourcetype: str = "_json"):
        payload = {
            "event": event_data,
            "sourcetype": sourcetype
        }
        
        async with aiohttp.ClientSession() as session:
            # Note: in production verify_ssl should be configured properly based on internal CA
            async with session.post(self.hec_url, json=payload, headers=self.headers, ssl=False) as response:
                if response.status in (200, 201):
                    logger.info("Successfully sent event to Splunk")
                    return await response.json()
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to send to Splunk: {response.status} {error_text}")
                    raise Exception("Splunk HEC Error")
