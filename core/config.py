from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # App Config
    APP_NAME: str = "DARIP API"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Neo4j Graph DB Config
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"

    # Kafka Config
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9092"
    KAFKA_INGESTION_TOPIC: str = "ingestion-events"
    KAFKA_FUSION_TOPIC: str = "fusion-events"

    # Relational DB Config (Optional depending on usage)
    DATABASE_URL: Optional[str] = "sqlite:///./darip.db"

    # Observability
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
