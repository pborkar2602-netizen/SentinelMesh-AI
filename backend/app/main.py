import time
import json
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import settings
from backend.app.db.database import init_db
from backend.app.api.gateway import router as gateway_router
from backend.app.api.events import router as events_router
from backend.app.api.agents import router as agents_router
from backend.app.api.policies import router as policies_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.audit import router as audit_router
from backend.app.api.privacy import router as privacy_router
from backend.app.api.auth import router as auth_router
from backend.app.api.approvals import router as approvals_router
from backend.app.api.stats import router as stats_router
from backend.app.mcp.proxy import router as mcp_router
from backend.app.api.websocket import ws_manager
from backend.app.core.policy_engine import PolicyEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinelmesh")

@asynccontextmanager
async def lifespan(app: FastAPI):
    import os
    demo_mode = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")
    vault_key = os.getenv("SENTINEL_VAULT_KEY")
    jwt_secret = os.getenv("SENTINEL_JWT_SECRET")
    token_secret = os.getenv("SENTINEL_TOKEN_SECRET")

    if not demo_mode:
        if not vault_key or not jwt_secret or not token_secret:
            err_msg = (
                "FATAL: SentinelMesh AI refused to start. Production mode requires "
                "SENTINEL_VAULT_KEY, SENTINEL_JWT_SECRET, and SENTINEL_TOKEN_SECRET environment variables. "
                "To run with ephemeral developer keys in non-production environments, set DEMO_MODE=true."
            )
            logger.error(err_msg)
            raise RuntimeError(err_msg)
        if token_secret == jwt_secret:
            err_msg = "FATAL: SENTINEL_TOKEN_SECRET and SENTINEL_JWT_SECRET must be separate cryptographic secrets."
            logger.error(err_msg)
            raise RuntimeError(err_msg)
    else:
        logger.warning("=" * 80)
        logger.warning("!!! SECURITY WARNING: SENTINELMESH RUNNING IN DEMO_MODE=true !!!")
        logger.warning("Ephemeral vault keys and demo user accounts are active. NEVER run DEMO_MODE in production!")
        logger.warning("=" * 80)

    logger.info("Initializing SentinelMesh AI Security Gateway...")
    init_db()
    logger.info("SentinelMesh Gateway ready to intercept agent tool calls.")
    yield
    logger.info("Shutting down SentinelMesh Gateway.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous, privacy-preserving security gateway for AI agents.",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(gateway_router, prefix=settings.API_V1_STR)
app.include_router(events_router, prefix=settings.API_V1_STR)
app.include_router(agents_router, prefix=settings.API_V1_STR)
app.include_router(policies_router, prefix=settings.API_V1_STR)
app.include_router(incidents_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(privacy_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(approvals_router, prefix=settings.API_V1_STR)
app.include_router(stats_router, prefix=settings.API_V1_STR)
app.include_router(mcp_router, prefix=settings.API_V1_STR)
app.include_router(mcp_router, prefix="")

@app.websocket("/ws/events")
async def websocket_event_feed(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open; receive client pings
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        logger.warning(f"WebSocket client error: {e}")
        ws_manager.disconnect(websocket)

@app.middleware("http")
async def add_timing_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    response.headers["X-Process-Time-Ms"] = f"{elapsed_ms:.3f}"

    # Structured JSON log (omitting raw request body to preserve privacy / zero raw PII)
    if not request.url.path.endswith("/health") and not request.url.path.endswith("/metrics"):
        log_payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "latency_ms": round(elapsed_ms, 2),
            "client_ip": request.client.host if request.client else "unknown",
        }
        logger.info(json.dumps(log_payload))

    return response

@app.get("/health", tags=["Health"])
@app.get(f"{settings.API_V1_STR}/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "mode": PolicyEngine.get_mode()
    }

@app.get("/metrics", tags=["Observability"])
@app.get(f"{settings.API_V1_STR}/metrics", tags=["Observability"])
def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    from backend.app.core.defense_in_depth import PrometheusMetrics
    return PlainTextResponse(
        content=PrometheusMetrics.export_metrics(),
        media_type="text/plain; version=0.0.4; charset=utf-8"
    )

@app.post("/echo", tags=["Diagnostics"])
@app.post(f"{settings.API_V1_STR}/echo", tags=["Diagnostics"])
async def echo_endpoint(payload: dict = None):
    return {"status": "ok", "echo": payload or {}}
