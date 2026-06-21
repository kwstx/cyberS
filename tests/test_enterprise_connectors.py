import pytest
from unittest.mock import MagicMock, patch
from pydantic import SecretStr

from data_ingestion.enterprise.crowdstrike_connector import CrowdStrikeConnector, CrowdStrikeConfig
from data_ingestion.enterprise.active_directory import ActiveDirectoryConnector, ADConfig

@pytest.mark.asyncio
async def test_crowdstrike_connector():
    config = CrowdStrikeConfig(client_id="fake_id", client_secret=SecretStr("fake_secret"))
    
    with patch('data_ingestion.enterprise.crowdstrike_connector.Detects') as MockDetects, \
         patch('data_ingestion.enterprise.crowdstrike_connector.Incidents') as MockIncidents:
         
        mock_detects_instance = MockDetects.return_value
        mock_detects_instance.query_detects.return_value = {"status_code": 200, "body": {"resources": ["ldt_123"]}}
        mock_detects_instance.get_detect_summaries.return_value = {
            "status_code": 200, 
            "body": {"resources": [{"detection_id": "ldt_123", "status": "new"}]}
        }
        
        connector = CrowdStrikeConnector(config)
        detections = await connector.fetch_recent_detections(limit=1)
        
        assert len(detections) == 1
        assert detections[0]["detection_id"] == "ldt_123"
        assert detections[0]["status"] == "new"

def test_active_directory_connector():
    config = ADConfig(
        server_uri="ldap://ad.local",
        bind_dn="CN=Admin",
        bind_password=SecretStr("secret"),
        search_base="DC=local"
    )
    
    with patch('data_ingestion.enterprise.active_directory.Server') as MockServer, \
         patch('data_ingestion.enterprise.active_directory.Connection') as MockConnection:
         
        mock_conn_instance = MockConnection.return_value
        
        # Mock a search result
        mock_entry = MagicMock()
        mock_entry.entry_dn = "CN=John Doe,DC=local"
        mock_entry.cn = "John Doe"
        mock_entry.sAMAccountName = "jdoe"
        mock_entry.userPrincipalName = "jdoe@local"
        mock_entry.memberOf = ["CN=Admins,DC=local"]
        mock_entry.userAccountControl.value = 512 # Normal account
        
        mock_conn_instance.entries = [mock_entry]
        
        connector = ActiveDirectoryConnector(config)
        connector._connection = mock_conn_instance # simulate connected state
        
        users = connector.fetch_users()
        
        assert len(users) == 1
        assert users[0]["username"] == "jdoe"
        assert users[0]["is_disabled"] == False
