import aiohttp
import logging
import base64
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger("connectors.sentinel")

class SentinelConnector:
    def __init__(self, workspace_id: str, shared_key: str):
        self.workspace_id = workspace_id
        self.shared_key = shared_key

    def _build_signature(self, date: str, content_length: int, method: str, content_type: str, resource: str) -> str:
        x_headers = f'x-ms-date:{date}'
        string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
        bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
        decoded_key = base64.b64decode(self.shared_key)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
        return f"SharedKey {self.workspace_id}:{encoded_hash}"

    async def send_log(self, log_data: Dict[str, Any], log_type: str):
        import json
        body = json.dumps(log_data)
        rfc1123date = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        
        signature = self._build_signature(rfc1123date, content_length, 'POST', 'application/json', '/api/logs')
        
        uri = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        
        headers = {
            'content-type': 'application/json',
            'Authorization': signature,
            'Log-Type': log_type,
            'x-ms-date': rfc1123date
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(uri, data=body, headers=headers) as response:
                if response.status in (200, 202):
                    logger.info("Successfully sent data to Azure Sentinel Log Analytics")
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to send to Sentinel: {response.status} {error_text}")
                    raise Exception("Sentinel API Error")
