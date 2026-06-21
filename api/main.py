import logging
import time
import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings

from api.routers import assets, scans, insights, exports, developer_portal, compliance
from connectors.webhooks import receiver as webhooks_router
from api.events import publisher
from core.observability import setup_observability

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from strawberry.fastapi import GraphQLRouter
from api.graphql import schema

logger = structlog.get_logger("api.main")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title=settings.APP_NAME,
    description="DARIP API Layer for EASM and Supply Chain Risk",
    version="1.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

setup_observability(app, "api_layer")

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
app.include_router(webhooks_router.router)
app.include_router(developer_portal.router)
app.include_router(compliance.router)

graphql_app = GraphQLRouter(schema)
app.include_router(graphql_app, prefix="/graphql")

@app.get("/health")
@limiter.limit("5/minute")
async def health_check(request: Request):
    return {"status": "ok", "environment": settings.ENVIRONMENT}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
