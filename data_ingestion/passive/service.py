import logging
import json
import os
from typing import Dict, Type
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from aiokafka import AIOKafkaProducer

from data_ingestion.passive.models import JobConfig, IngestionResult
from data_ingestion.passive.base_connector import BaseAPIConnector

logger = logging.getLogger("PassiveIngestion.Service")

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "darip-raw-signals"

class PassiveIngestionService:
    """
    Manages background ingestion jobs using APScheduler.
    Instantiates connectors based on config and schedules them to pull data periodically.
    """
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.connectors: Dict[str, BaseAPIConnector] = {}
        self.connector_registry: Dict[str, Type[BaseAPIConnector]] = {}
        self.kafka_producer = None

    def register_connector_class(self, name: str, connector_cls: Type[BaseAPIConnector]):
        """Register a new connector class type."""
        self.connector_registry[name] = connector_cls

    async def start(self):
        """Start the scheduler and initialize resources like Kafka producer."""
        logger.info("Starting Passive Ingestion Service scheduler...")
        
        # Initialize Kafka Producer
        self.kafka_producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            acks='all'
        )
        await self.kafka_producer.start()
        
        self.scheduler.start()

    async def stop(self):
        """Stop the scheduler and close all connector clients."""
        logger.info("Stopping Passive Ingestion Service...")
        self.scheduler.shutdown(wait=False)
        for connector in self.connectors.values():
            await connector.close()
            
        if self.kafka_producer:
            await self.kafka_producer.stop()

    async def run_job(self, job_config: JobConfig):
        """
        The actual coroutine that runs on schedule.
        Fetches data using the connector and publishes it to Kafka.
        """
        logger.info(f"Running ingestion job: {job_config.job_id}")
        
        if job_config.job_id not in self.connectors:
            if job_config.connector_class not in self.connector_registry:
                logger.error(f"Connector class {job_config.connector_class} not registered.")
                return
            
            cls = self.connector_registry[job_config.connector_class]
            self.connectors[job_config.job_id] = cls(job_config.connector_config)

        connector = self.connectors[job_config.job_id]
        
        try:
            result: IngestionResult = await connector.fetch_data(job_config.job_id)
            
            if result.errors:
                logger.warning(f"Job {job_config.job_id} encountered errors: {result.errors}")
            elif result.payload:
                logger.info(f"Job {job_config.job_id} succeeded. Publishing to Kafka.")
                await self._publish_to_kafka(result)
            else:
                logger.info(f"Job {job_config.job_id} returned no data.")
                
        except Exception as e:
            logger.error(f"Unexpected error running job {job_config.job_id}: {e}")

    async def _publish_to_kafka(self, result: IngestionResult):
        if not self.kafka_producer:
            logger.error("Kafka producer not initialized.")
            return
            
        # Structure payload for darip-raw-signals topic
        message = {
            "source": result.source_name,
            "type": "passive_ingestion",
            "job_id": result.job_id,
            "timestamp": result.timestamp,
            "provenance": {
                "request_params": result.request_params,
                "response_status": result.response_status
            },
            "data": result.payload
        }
        
        await self.kafka_producer.send_and_wait(KAFKA_TOPIC, json.dumps(message).encode('utf-8'))

    def schedule_job(self, config: JobConfig):
        """Schedule a new ingestion job based on configuration."""
        if config.cron_schedule:
            self.scheduler.add_job(
                self.run_job, 
                'cron', 
                args=[config], 
                id=config.job_id,
                replace_existing=True,
                **self._parse_cron(config.cron_schedule)
            )
            logger.info(f"Scheduled cron job {config.job_id} with schedule {config.cron_schedule}")
        elif config.interval_seconds:
            self.scheduler.add_job(
                self.run_job,
                'interval',
                seconds=config.interval_seconds,
                args=[config],
                id=config.job_id,
                replace_existing=True
            )
            logger.info(f"Scheduled interval job {config.job_id} every {config.interval_seconds}s")
        else:
            logger.error("Job config must provide cron_schedule or interval_seconds.")

    def _parse_cron(self, cron_str: str) -> Dict[str, str]:
        """A simple helper to parse basic cron strings for APScheduler."""
        parts = cron_str.split()
        if len(parts) != 5:
            raise ValueError("Cron string must have 5 parts (minute, hour, day, month, day_of_week)")
        return {
            "minute": parts[0],
            "hour": parts[1],
            "day": parts[2],
            "month": parts[3],
            "day_of_week": parts[4]
        }
