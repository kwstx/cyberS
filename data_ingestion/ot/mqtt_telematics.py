import logging
import json
import ssl
from typing import Dict, Any, List
from pydantic import BaseModel, SecretStr
import paho.mqtt.client as mqtt

logger = logging.getLogger(__name__)

class MQTTConfig(BaseModel):
    broker_url: str
    port: int = 8883
    client_id: str
    username: str
    password: SecretStr
    topics: List[str]
    use_tls: bool = True

class MQTTTelematicsConnector:
    """
    Production-ready OT connector for MQTT Telematics.
    Used for ingesting fleet GPS, engine metrics, and remote asset state securely.
    """
    def __init__(self, config: MQTTConfig):
        self.config = config
        self.client = mqtt.Client(client_id=self.config.client_id)
        
        if self.config.username and self.config.password:
            self.client.username_pw_set(
                self.config.username, 
                self.config.password.get_secret_value()
            )
            
        if self.config.use_tls:
            self.client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
            
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect
        
        self.message_buffer = []

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"Connected to MQTT Broker at {self.config.broker_url}")
            for topic in self.config.topics:
                client.subscribe(topic)
                logger.info(f"Subscribed to topic: {topic}")
        else:
            logger.error(f"Failed to connect to MQTT Broker, return code {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            telemetry = {
                "topic": msg.topic,
                "qos": msg.qos,
                "payload": payload
            }
            self.message_buffer.append(telemetry)
        except json.JSONDecodeError:
            logger.warning(f"Received non-JSON MQTT message on {msg.topic}")
        except Exception as e:
            logger.exception(f"Error processing MQTT message: {e}")

    def _on_disconnect(self, client, userdata, rc):
        logger.warning(f"Disconnected from MQTT Broker with return code {rc}")

    def start(self):
        """
        Starts the MQTT client loop in a background thread.
        """
        try:
            self.client.connect(self.config.broker_url, self.config.port, 60)
            self.client.loop_start()
        except Exception as e:
            logger.exception(f"Exception starting MQTT client: {e}")

    def stop(self):
        """
        Stops the background loop and disconnects.
        """
        self.client.loop_stop()
        self.client.disconnect()

    def flush_messages(self) -> List[Dict[str, Any]]:
        """
        Retrieves and clears the internal message buffer.
        """
        messages = self.message_buffer.copy()
        self.message_buffer.clear()
        return messages
