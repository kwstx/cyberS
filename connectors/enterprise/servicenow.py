import aiohttp
import logging
import base64
from typing import Dict, Any

logger = logging.getLogger("connectors.servicenow")

class ServiceNowConnector:
    def __init__(self, instance_url: str, username: str, password: str):
        self.instance_url = instance_url
        self.username = username
        self.password = password
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode('utf-8')
        self.headers = {
            "Authorization": f"Basic {self._auth}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def create_incident(self, description: str, short_description: str) -> Dict[str, Any]:
        url = f"{self.instance_url}/api/now/table/incident"
        payload = {
            "short_description": short_description,
            "description": description,
            "urgency": "1",
            "impact": "2"
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=self.headers) as response:
                if response.status == 201:
                    data = await response.json()
                    logger.info(f"Created ServiceNow Incident: {data['result']['number']}")
                    return data['result']
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to create incident: {response.status} {error_text}")
                    raise Exception("ServiceNow API Error")

    async def pull_cmdb_assets(self, limit: int = 100):
        url = f"{self.instance_url}/api/now/table/cmdb_ci?sysparm_limit={limit}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('result', [])
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to pull CMDB: {response.status} {error_text}")
                    raise Exception("ServiceNow API Error")
