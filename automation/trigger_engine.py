import faust
import logging
import asyncio
from typing import Dict, Any
from api.pep import pep_engine
from connectors.enterprise.ariba import AribaConnector

logger = logging.getLogger("automation.trigger_engine")

# Initialize Faust App
app = faust.App(
    'darip-trigger-engine',
    broker='kafka://localhost:9092',
    value_serializer='json',
)

insights_topic = app.topic('darip-insights')

# Mock initialization of Ariba Connector
ariba_connector = AribaConnector(api_key="mock_key", realm="mock_realm")

@app.agent(insights_topic)
async def process_insights(insights):
    """
    Subscribes to DARIP Risk Insights and triggers external actions.
    """
    async for insight in insights:
        try:
            insight_type = insight.get("type")
            severity = insight.get("severity", "info")
            vendor_id = insight.get("vendor_id")
            
            logger.info(f"Received insight: {insight_type} for Vendor {vendor_id} (Severity: {severity})")
            
            # Example Scenario: High exploitability on a vendor triggers a block
            if insight_type == "critical_vendor_vulnerability" and vendor_id:
                action = "block_vendor"
                
                # 1. Policy Enforcement Point (PEP) Evaluation
                if pep_engine.evaluate_outbound_action(action, severity, context=insight):
                    # 2. Trigger Action via Connector
                    logger.info("PEP Approved. Triggering external Ariba connector...")
                    
                    payload = {"vendor_id": vendor_id, "reason": f"Automated block via DARIP: {insight.get('title')}"}
                    
                    # Call async push_action
                    result = await ariba_connector.push_action(action, payload)
                    logger.info(f"Action Execution Result: {result}")
                else:
                    logger.warning("PEP Denied the action. Escalating to human review ticket.")
                    # Fallback could be: create_incident() via ServiceNowConnector
                    
        except Exception as e:
            logger.error(f"Error processing insight trigger: {e}")

if __name__ == '__main__':
    # Usage: faust -A automation.trigger_engine worker -l info
    app.main()
