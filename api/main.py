import logging
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings

from api.routers import assets, scans, insights, exports
from api.events import publisher

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("api.main")

app = FastAPI(
    title=settings.APP_NAME,
    description="DARIP API Layer for EASM and Supply Chain Risk",
    version="1.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Should be restricted in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(f"{request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.4f}s")
    return response

# Lifecycle events
@app.on_event("startup")
async def startup_event():
    logger.info("Starting up DARIP API...")
    await publisher.connect()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down DARIP API...")
    await publisher.disconnect()

# Include routers
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(insights.router)
app.include_router(exports.router)

@app.get("/health")
async def health_check():
    return {"status": "ok", "environment": settings.ENVIRONMENT}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
