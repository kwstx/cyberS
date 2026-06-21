import pytest
from unittest.mock import MagicMock, patch
from pydantic import SecretStr

# Import our connectors
from data_ingestion.ot.modbus_connector import ModbusConnector, ModbusConfig
from data_ingestion.ot.mqtt_telematics import MQTTTelematicsConnector, MQTTConfig

def test_modbus_connector_read():
    config = ModbusConfig(host="10.0.0.1", port=502, unit_id=1, register_start=0, register_count=10)
    
    with patch('data_ingestion.ot.modbus_connector.ModbusTcpClient') as MockClient:
        # Mock successful connection
        mock_instance = MockClient.return_value
        mock_instance.connect.return_value = True
        
        # Mock successful read
        mock_result = MagicMock()
        mock_result.isError.return_value = False
        mock_result.registers = [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
        mock_instance.read_holding_registers.return_value = mock_result
        
        connector = ModbusConnector(config)
        connector.connect()
        telemetry = connector.read_telemetry()
        
        assert telemetry["status"] == "ok"
        assert telemetry["protocol"] == "modbus_tcp"
        assert len(telemetry["data"]) == 10
        assert telemetry["data"][0] == 100

def test_mqtt_telematics_buffer():
    config = MQTTConfig(
        broker_url="mqtt.warehouse.local",
        client_id="test_client",
        username="admin",
        password=SecretStr("secret"),
        topics=["telemetry/trucks/#"]
    )
    
    with patch('data_ingestion.ot.mqtt_telematics.mqtt.Client') as MockMQTT:
        connector = MQTTTelematicsConnector(config)
        
        # Manually trigger on_message callback
        mock_msg = MagicMock()
        mock_msg.topic = "telemetry/trucks/123"
        mock_msg.qos = 1
        mock_msg.payload = b'{"gps": "51.5,-0.1", "speed": 65}'
        
        connector._on_message(None, None, mock_msg)
        
        messages = connector.flush_messages()
        
        assert len(messages) == 1
        assert messages[0]["topic"] == "telemetry/trucks/123"
        assert messages[0]["payload"]["speed"] == 65
        
        # Assert buffer is flushed
        assert len(connector.message_buffer) == 0
