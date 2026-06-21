import aiohttp
import logging
from typing import Dict, Any

logger = logging.getLogger("connectors.jira")

class JiraConnector:
    def __init__(self, base_url: str, username: str, api_token: str, project_key: str):
        self.base_url = base_url
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
        
        auth_string = f"{username}:{api_token}"
        import base64
        self.auth_header = "Basic " + base64.b64encode(auth_string.encode()).decode('utf-8')
        
    async def create_issue(self, summary: str, description: str, issue_type: str = "Bug") -> Dict[str, Any]:
        url = f"{self.base_url}/rest/api/3/issue"
        headers = {
            "Authorization": self.auth_header,
            "Content-Type": "application/json"
        }
        
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary,
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {"type": "text", "text": description}
                            ]
                        }
                    ]
                },
                "issuetype": {"name": issue_type}
            }
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status == 201:
                    data = await response.json()
                    logger.info(f"Created Jira Issue: {data['key']}")
                    return data
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to create Jira issue: {response.status} {error_text}")
                    raise Exception("Jira API Error")
