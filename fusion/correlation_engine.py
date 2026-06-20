import json
import logging
import asyncio
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from aiokafka import AIOKafkaConsumer

from core.models import Asset, Exposure, Relationship, RelationshipType, AssetType
from storage.graph import GraphRepository
from core.config import settings

logger = logging.getLogger("DARIP.CorrelationEngine")

class AssetLinker:
    """
    Uses NLP embeddings (TF-IDF with character n-grams) to fuzzy match
    asset names, hostnames, or other text properties when strict matching fails.
    """
    def __init__(self, threshold: float = 0.85):
        self.threshold = threshold
        self.vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(2, 4))
        self.candidates: List[Dict[str, Any]] = []
        self.candidate_texts: List[str] = []
        self.embeddings = None

    def fit_candidates(self, candidates: List[Dict[str, Any]]):
        self.candidates = candidates
        # Create a document for each candidate combining relevant fields
        self.candidate_texts = []
        for cand in candidates:
            # e.g., combining id, value, and name
            doc = f"{cand.get('value', '')} {cand.get('name', '')}"
            self.candidate_texts.append(doc)
            
        if self.candidate_texts:
            self.embeddings = self.vectorizer.fit_transform(self.candidate_texts)
        else:
            self.embeddings = None

    def find_best_match(self, query_asset: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], float]:
        if not self.candidate_texts or self.embeddings is None:
            return None, 0.0
            
        query_doc = f"{query_asset.get('value', '')} {query_asset.get('name', '')}"
        try:
            query_vec = self.vectorizer.transform([query_doc])
            sims = cosine_similarity(query_vec, self.embeddings)[0]
            best_idx = np.argmax(sims)
            best_score = sims[best_idx]
            
            if best_score >= self.threshold:
                return self.candidates[best_idx], best_score
        except Exception as e:
            logger.error(f"Error during fuzzy matching: {e}")
            
        return None, 0.0


class CorrelationEngine:
    def __init__(self, graph_repo: GraphRepository):
        self.graph_repo = graph_repo
        self.linker = AssetLinker(threshold=0.85)

    async def _fetch_candidates(self):
        """Fetch candidates from the graph to populate the linker."""
        candidates = await self.graph_repo.get_all_assets()
        # Keep only internal assets or known hosts as candidates
        internal_candidates = [
            cand for cand in candidates 
            if cand.get("type") in [AssetType.HOST.value, AssetType.CLOUD_RESOURCE.value] 
            or cand.get("id", "").startswith("asset--splunk")
            or cand.get("id", "").startswith("asset--sentinel")
        ]
        self.linker.fit_candidates(internal_candidates)
        return internal_candidates

    async def correlate_asset(self, incoming_asset_dict: Dict[str, Any]):
        """
        Correlates an incoming asset (e.g., external discovery) with internal inventory.
        Applies conflict resolution rules and stores the fused asset.
        """
        # Update candidates periodically or before processing
        await self._fetch_candidates()
        
        # 1. Exact Property Match (e.g., Certificate Hash, IP address)
        matched_candidate = None
        match_score = 0.0
        incoming_props = incoming_asset_dict.get("properties", {})
        incoming_value = incoming_asset_dict.get("value", "")
        
        for cand in self.linker.candidates:
            cand_props = cand.get("properties", {})
            cand_value = cand.get("value", "")
            
            # Exact value match
            if incoming_value and incoming_value == cand_value:
                matched_candidate = cand
                match_score = 1.0
                break
            
            # Certificate Hash match
            inc_cert = incoming_props.get("cert_hash")
            cand_cert = cand_props.get("cert_hash")
            if inc_cert and cand_cert and inc_cert == cand_cert:
                matched_candidate = cand
                match_score = 1.0
                break

        # 2. Fuzzy Match (if exact match fails)
        if not matched_candidate:
            matched_candidate, match_score = self.linker.find_best_match(incoming_asset_dict)

        incoming_asset = Asset(**incoming_asset_dict)

        # 3. Conflict Resolution & Fusion
        if matched_candidate:
            cand_asset = Asset(**matched_candidate)
            logger.info(f"Correlated {incoming_asset.id} with {cand_asset.id} (Score: {match_score:.2f})")
            
            # Conflict Resolution: Internal Metadata takes precedence
            fused_properties = {**incoming_asset.properties, **cand_asset.properties}
            
            # Keep candidate's ID and type as the primary node
            fused_asset = cand_asset.copy(update={
                "properties": fused_properties,
                "updated_at": datetime.now(timezone.utc)
            })
            
            await self.graph_repo.upsert_asset(fused_asset)
            
            # Create a RESOLVES_TO relationship
            rel = Relationship(
                source_id=incoming_asset.id,
                target_id=fused_asset.id,
                relationship_type=RelationshipType.RESOLVES_TO,
                confidence_score=match_score
            )
            await self.graph_repo.upsert_asset(incoming_asset)
            await self.graph_repo.upsert_relationship(rel)
            
        else:
            logger.info(f"No correlation found for {incoming_asset.id}. Storing as new asset.")
            await self.graph_repo.upsert_asset(incoming_asset)

    async def consume_events(self):
        """Runs the Kafka consumer to process incoming fusion events."""
        consumer = AIOKafkaConsumer(
            settings.KAFKA_FUSION_TOPIC,
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            group_id="darip-fusion-group",
            auto_offset_reset="earliest"
        )
        await consumer.start()
        logger.info(f"CorrelationEngine listening on Kafka topic: {settings.KAFKA_FUSION_TOPIC}")
        try:
            async for msg in consumer:
                try:
                    event_data = json.loads(msg.value.decode('utf-8'))
                    logger.info(f"Received fusion event: {event_data.get('id')}")
                    await self.correlate_asset(event_data)
                except json.JSONDecodeError:
                    logger.error("Failed to decode JSON from Kafka message.")
                except Exception as e:
                    logger.error(f"Error processing fusion event: {e}")
        finally:
            await consumer.stop()

    async def start(self):
        """Starts the Kafka consumer loop as a background task."""
        asyncio.create_task(self.consume_events())
