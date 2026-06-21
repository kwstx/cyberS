import logging
from typing import Dict, Any, List
from pydantic import BaseModel
from pymodbus.client import ModbusTcpClient

logger = logging.getLogger(__name__)

class ModbusConfig(BaseModel):
    host: str
    port: int = 502
    unit_id: int = 1
    register_start: int = 0
    register_count: int = 100

class ModbusConnector:
    """
    Production-ready OT connector for Modbus/TCP.
    Connects to industrial PLCs (Programmable Logic Controllers) used in warehouses.
    """
    def __init__(self, config: ModbusConfig):
        self.config = config
        self.client = ModbusTcpClient(self.config.host, port=self.config.port)
        self.connected = False

    def connect(self) -> bool:
        try:
            self.connected = self.client.connect()
            if self.connected:
                logger.info(f"Connected to Modbus PLC at {self.config.host}:{self.config.port}")
            else:
                logger.warning(f"Failed to connect to Modbus PLC at {self.config.host}:{self.config.port}")
            return self.connected
        except Exception as e:
            logger.error(f"Exception connecting to Modbus: {e}")
            return False

    def disconnect(self):
        if self.connected:
            self.client.close()
            self.connected = False

    def read_telemetry(self) -> Dict[str, Any]:
        """
        Reads holding registers from the PLC.
        """
        if not self.connected:
             if not self.connect():
                 return {}

        try:
            # Read holding registers (Function Code 3)
            result = self.client.read_holding_registers(
                address=self.config.register_start,
                count=self.config.register_count,
                slave=self.config.unit_id
            )
            
            if result.isError():
                logger.error(f"Modbus read error: {result}")
                return {}
                
            registers = result.registers
            return {
                "host": self.config.host,
                "protocol": "modbus_tcp",
                "unit_id": self.config.unit_id,
                "start_address": self.config.register_start,
                "data": registers,
                "status": "ok"
            }
        except Exception as e:
            logger.exception(f"Exception reading Modbus registers: {e}")
            return {}
