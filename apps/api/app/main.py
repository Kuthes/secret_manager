import logging
import time
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from apps.api.app.core.config import settings
from apps.api.app.api.v1.router import api_router
from apps.api.app.db.session import engine, Base, async_session_factory
from apps.api.app.services.seed_service import seed_service
import apps.api.app.models  # Ensure all models are registered

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","message":"%(message)s"}',
)
logger = logging.getLogger("aegisvault")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing AegisVault database schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified.")

    if settings.DEMO_MODE:
        logger.info("DEMO_MODE=true: Verifying demo workspace seed...")
        async with async_session_factory() as session:
            await seed_service.seed_demo_data(session)
        logger.info("Demo workspace seeded: user='demo@aegisvault.local', org='Acme Cloud'.")

    yield

    logger.info("Shutting down AegisVault API engine...")
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# CORS Middleware with strict origin whitelist
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_and_telemetry_middleware(request: Request, call_next):
    req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    start_time = time.time()

    response: Response = await call_next(request)

    # Security Headers
    response.headers["X-Request-ID"] = req_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    duration = round((time.time() - start_time) * 1000, 2)
    # Log request securely (never logging bodies or auth credentials)
    logger.info(f"{request.method} {request.url.path} -> {response.status_code} ({duration}ms)")

    return response


app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "service": "AegisVault Enterprise Security Control Plane",
        "version": "1.0.0",
        "docs": f"{settings.API_V1_STR}/docs",
    }
