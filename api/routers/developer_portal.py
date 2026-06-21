from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse
import logging

logger = logging.getLogger("api.developer_portal")
router = APIRouter(prefix="/portal", tags=["Developer Portal"])

PORTAL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>DARIP Developer Portal</title>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        h1 { color: #bb86fc; }
        .card { background: #2c2c2c; padding: 20px; margin-bottom: 20px; border-radius: 8px; border-left: 4px solid #bb86fc; }
        code { background: #121212; padding: 5px; border-radius: 4px; color: #03dac6; font-size: 1.1em; }
        pre { background: #121212; padding: 15px; border-radius: 8px; overflow-x: auto; color: #a5d6a7; }
        .btn { background-color: #bb86fc; color: #000; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DARIP Self-Service Developer Portal</h1>
        <p>Achieve 10x connectivity by integrating your external systems with DARIP in days, not months. Use our standardized webhook templates below.</p>
        
        <div class="card">
            <h2>1. Register a Webhook Receiver</h2>
            <p>Send external events directly to our generic webhook endpoint to update the Risk Graph dynamically.</p>
            <pre>POST /webhooks/generic
Content-Type: application/json
X-API-Key: &lt;YOUR_API_KEY&gt;

{
  "source": "custom_hr_system",
  "event_type": "employee_offboarding",
  "data": { "employee_id": "12345", "status": "terminated" }
}</pre>
        </div>

        <div class="card">
            <h2>2. Subscribe to Risk Insights</h2>
            <p>Listen to our normalized risk insights to trigger automated actions in your tools.</p>
            <p>Subscribe via Kafka Topic: <code>darip-insights</code></p>
            <a href="/docs" class="btn">View Full OpenAPI Spec</a>
        </div>
    </div>
</body>
</html>
"""

@router.get("/", response_class=HTMLResponse)
async def developer_portal_home():
    """
    Renders the self-service developer portal.
    """
    return HTMLResponse(content=PORTAL_HTML)
