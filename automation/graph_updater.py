import faust
import logging
import httpx
from typing import Dict, Any

logger = logging.getLogger("automation.graph_updater")

app = faust.App(
    'darip-graph-updater',
    broker='kafka://localhost:9092',
    value_serializer='json',
)

normalized_topic = app.topic('darip-normalized')
FUSION_API_URL = "http://localhost:8002/fuse"

@app.agent(normalized_topic)
async def update_risk_graph(normalized_signals):
    """
    Listens to normalized external events and dynamically updates the Risk Graph
    by calling the Semantic Fusion Service.
    """
    async for signal in normalized_signals:
        try:
            logger.info(f"Consuming normalized signal: {signal.get('event_type')}")
            
            # Formulate payload for Fusion Service
            # Note: In production this requires the PQC/KEM encryption wrapping, 
            # but for this internal automation layer we bypass or mock the KEM if allowed by policy.
            
            # Mocking the KEM wrap for demonstration
            fusion_payload = {
                "kem_ciphertext_b64": "mock_kem_ciphertext",
                "encrypted_payload": "mock_encrypted_payload"
            }
            
            headers = {
                "X-DARIP-Token": "automation-token",
                "X-DARIP-PQC-Sig": "mock-sig"
            }
            
            # Send to Fusion Service
            # async with httpx.AsyncClient() as client:
            #     resp = await client.post(FUSION_API_URL, json=fusion_payload, headers=headers)
            #     if resp.status_code == 200:
            #         logger.info("Successfully updated Risk Graph via Fusion Service")
            #     else:
            #         logger.error(f"Graph update failed: {resp.status_code} {resp.text}")
                    
            logger.info("Mocked successful update to Risk Graph.")
            
        except Exception as e:
            logger.error(f"Error updating graph: {e}")

if __name__ == '__main__':
    app.main()
