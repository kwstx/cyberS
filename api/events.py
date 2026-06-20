import json
import logging
from typing import Any, Dict
from aiokafka import AIOKafkaProducer
from core.config import settings

logger = logging.getLogger("api.events")

class EventPublisher:
    def __init__(self):
        self.producer = None
        self.bootstrap_servers = settings.KAFKA_BOOTSTRAP_SERVERS

    async def connect(self):
        try:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            await self.producer.start()
            logger.info(f"Connected to Kafka broker at {self.bootstrap_servers}")
        except Exception as e:
            logger.error(f"Failed to connect to Kafka broker: {e}")
            self.producer = None

    async def disconnect(self):
        if self.producer:
            await self.producer.stop()
            logger.info("Disconnected from Kafka broker")

    async def publish_event(self, topic: str, event_data: Dict[str, Any]):
        if not self.producer:
            logger.warning("Kafka producer not initialized. Falling back to webhook/logger.")
            logger.info(f"[WEBHOOK FALLBACK] Emitting to {topic}: {event_data}")
            return
        
        try:
            await self.producer.send_and_wait(topic, event_data)
            logger.info(f"Published event to topic '{topic}'")
        except Exception as e:
            logger.error(f"Error publishing event to {topic}: {e}")

publisher = EventPublisher()
