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
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://darip.internal.net"
] if settings.ENVIRONMENT == "production" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "X-Client-Identity"],
)

# Zero-Trust & Hardening Security Middleware
@app.middleware("http")
async def secure_and_audit_requests(request: Request, call_next):
    # 1. Zero-Trust mTLS & IP Network Validation
    # In a zero-trust architecture, all endpoints verify client identity and network boundaries.
    client_ip = request.client.host if request.client else "unknown"
    client_identity = request.headers.get("X-Client-Identity", "anonymous")
    
    # Simulated zero-trust mTLS verification check via gateway injected headers
    client_verify = request.headers.get("X-SSL-Client-Verify", "NONE")
    
    # Log detailed zero trust telemetry
    logger.info(
        f"[Zero-Trust Audit] Request: {request.method} {request.url.path} "
        f"IP: {client_ip} Identity: {client_identity} mTLS: {client_verify}"
    )

    # For demonstration/testing, if a specific test header is passed asserting a fail, we reject
    if request.headers.get("X-Simulate-MTLS-Failure") == "true":
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=403,
            content={"detail": "Zero-Trust Enforcement: Valid client certificate (mTLS) required."}
        )

    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    
    # 2. Inject Security Hardening Headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    logger.info(
        f"{request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.4f}s"
    )
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
