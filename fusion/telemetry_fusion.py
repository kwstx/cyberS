import logging
import asyncio
import structlog
from typing import List, Dict, Any

from storage.graph import GraphRepository
from core.models import Asset, Exposure, AssetType, Relationship, RelationshipType
from fusion.correlation_engine import CorrelationEngine

logger = structlog.get_logger("DARIP.TelemetryFusion")

class TelemetryFusionService:
    """
    Periodically compares internal inventories against externally discovered assets 
    to identify shadow IT and unknown exposures.
    """
    
    def __init__(self, graph_repo: GraphRepository):
        self.graph_repo = graph_repo
        self.correlation_engine = CorrelationEngine(graph_repo)

    async def identify_shadow_it(self) -> List[Asset]:
        """
        Identify assets that exist in the external discovery graph but lack 
        a matching internal record (from Splunk, Sentinel, etc.).
        This requires a custom Cypher query to find nodes where external discovery 
        found them, but no internal tool claims ownership.
        """
        # A simple heuristic: find IPs/Domains that don't have a specific "source" property 
        # indicating internal telemetry like 'splunk' or 'microsoft_sentinel', 
        # or that aren't linked to a known internal HOST.
        
        query = """
        // Find external assets (e.g., discovered via shodan/censys)
        MATCH (a:Asset)
        WHERE (a.type = 'ipv4-addr' OR a.type = 'domain-name')
          AND NOT a.id STARTS WITH 'asset--splunk'
          AND NOT a.id STARTS WITH 'asset--sentinel'
        
        // Ensure they aren't linked to any internal host
        OPTIONAL MATCH (a)-[:RESOLVES_TO|HOSTS]-(internal:Asset)
        WHERE internal.type IN ['host', 'cloud-resource']
        
        WITH a, internal
        WHERE internal IS NULL
        RETURN a
        LIMIT 100
        """
        shadow_assets = []
        try:
            async with self.graph_repo.driver.session() as session:
                result = await session.run(query)
                records = await result.data()
                for record in records:
                    node_data = dict(record["a"])
                    # Convert raw dict back to Asset model (or just use dict if needed)
                    # For simplicity, we just return the raw dict wrapped in an Asset or just dicts.
                    # We'll construct a simplified Asset to return
                    asset = Asset(**node_data)
                    shadow_assets.append(asset)
        except Exception as e:
            logger.error(f"Error querying shadow IT: {e}")
            
        return shadow_assets

    async def flag_shadow_it_exposures(self):
        """
        Finds Shadow IT assets and creates Exposure nodes for them.
        """
        logger.info("Starting Shadow IT fusion scan...")
        shadow_assets = await self.identify_shadow_it()
        
        if not shadow_assets:
            logger.info("No new Shadow IT detected.")
            return

        logger.info(f"Detected {len(shadow_assets)} potential Shadow IT assets.")
        
        for asset in shadow_assets:
            exposure_id = f"exposure--shadow-it--{asset.id}"
            
            # Create an exposure
            exposure = Exposure(
                id=exposure_id,
                title="Unmanaged Shadow IT Asset",
                description=f"Asset {asset.value} ({asset.type}) was discovered externally but is not present in internal telemetry systems (Splunk/Sentinel).",
                severity="HIGH",
                remediation="Investigate the asset owner and onboard it into internal telemetry or decommission it."
            )
            
            # Upsert exposure
            await self.graph_repo.upsert_exposure(exposure)
            
            # Create relationship from Asset to Exposure
            rel = Relationship(
                source_id=asset.id,
                target_id=exposure.id,
                relationship_type=RelationshipType.HAS_EXPOSURE,
                confidence_score=0.9
            )
            
            await self.graph_repo.upsert_relationship(rel)
            logger.info(f"Flagged shadow IT exposure {exposure_id} for asset {asset.value}")

    async def run_fusion_loop(self, interval_seconds: int = 3600):
        """Run the fusion service periodically and start the correlation engine."""
        logger.info(f"Starting TelemetryFusionService with interval {interval_seconds}s")
        
        # Start Kafka correlation engine
        await self.correlation_engine.start()
        
        while True:
            try:
                await self.flag_shadow_it_exposures()
            except Exception as e:
                logger.error(f"Error during fusion loop: {e}")
            
            await asyncio.sleep(interval_seconds)
