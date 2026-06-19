import logging
import httpx
from typing import Dict, Any

logger = logging.getLogger("EnrichmentPipeline")

class EnrichmentPipeline:
    def __init__(self):
        # In a real scenario, this would use API keys to contact external providers
        self.mock_providers = ["SecurityScorecard", "BitSight"]

    async def fetch_external_rating(self, entity_name: str) -> Dict[str, Any]:
        """
        Mocks a call to an external rating provider.
        """
        # Simulated delay for API call
        # await asyncio.sleep(0.1) 
        import random
        provider = random.choice(self.mock_providers)
        score = random.randint(40, 100)
        return {
            "provider": provider,
            "external_score": score,
            "risk_tier": "Low" if score > 80 else "Medium" if score > 60 else "High"
        }

    def compute_proprietary_risk(self, data: Dict[str, Any], external_data: Dict[str, Any]) -> float:
        """
        Computes a proprietary DARIP risk score based on raw signals and external ratings.
        """
        base_score = external_data.get("external_score", 70)
        penalty = 0

        # Adjust score based on signals
        if data.get("type") == "vulnerability":
            severity = data.get("severity", "LOW")
            if severity == "CRITICAL":
                penalty += 30
            elif severity == "HIGH":
                penalty += 20
            elif severity == "MEDIUM":
                penalty += 10
        elif data.get("type") == "report":
            # Threat intel report
            penalty += 15
        elif data.get("type") == "sbom":
            deps = data.get("dependencies_count", 0)
            if deps > 30:
                penalty += 5 # Slight penalty for large attack surface
        
        final_score = max(0.0, base_score - penalty)
        return final_score

    async def enrich(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entrypoint for the enrichment pipeline.
        Takes raw unstructured/semi-structured data and normalizes/enriches it.
        """
        entity = raw_data.get("repo") or raw_data.get("package") or raw_data.get("actor") or "Unknown_Entity"
        
        external_rating = await self.fetch_external_rating(entity)
        darip_score = self.compute_proprietary_risk(raw_data, external_rating)

        enriched_payload = {
            "original_signal": raw_data,
            "enrichment": {
                "external_ratings": [external_rating],
                "darip_proprietary_score": darip_score,
                "normalized_entity": entity
            }
        }
        
        logger.info(f"Enriched signal for {entity} - Proprietary Score: {darip_score}")
        return enriched_payload
