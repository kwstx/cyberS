import faust
import logging
from typing import Dict, Any

logger = logging.getLogger("transformations.pipeline")

# Initialize Faust App
app = faust.App(
    'darip-transformation-pipeline',
    broker='kafka://localhost:9092',
    value_serializer='json',
)

raw_signals_topic = app.topic('darip-raw-signals')
normalized_topic = app.topic('darip-normalized')

@app.agent(raw_signals_topic)
async def process_raw_signals(signals):
    async for signal in signals:
        try:
            # Basic Schema Mapping
            source = signal.get("source", "unknown")
            normalized_data = {}
            
            if source == "github":
                normalized_data = {
                    "asset_type": "software",
                    "value": signal.get("repo"),
                    "event_type": "commit_scan",
                    "severity": "info",
                    "raw_data": signal
                }
            elif source == "pypi" or source == "npm":
                normalized_data = {
                    "asset_type": "software",
                    "value": signal.get("package"),
                    "event_type": "vulnerability" if source == "pypi" else "sbom",
                    "severity": signal.get("severity", "unknown").lower(),
                    "raw_data": signal
                }
            elif source == "network_scanner":
                normalized_data = {
                    "asset_type": "ipv4-addr",
                    "value": signal.get("ip_address"),
                    "event_type": "port_scan",
                    "open_ports": signal.get("open_ports", []),
                    "severity": "info",
                    "raw_data": signal
                }
            else:
                # Default fallback
                normalized_data = {
                    "asset_type": "unknown",
                    "value": "unknown",
                    "event_type": "generic_signal",
                    "severity": "info",
                    "raw_data": signal
                }
                
            # Enrichment (mocked)
            normalized_data["enriched"] = True
            normalized_data["processed_by"] = "faust-pipeline"
            
            # Forward to normalized topic
            await normalized_topic.send(value=normalized_data)
            logger.info(f"Processed and normalized signal from {source}")
            
        except Exception as e:
            logger.error(f"Error processing signal: {e}")

if __name__ == '__main__':
    app.main()
