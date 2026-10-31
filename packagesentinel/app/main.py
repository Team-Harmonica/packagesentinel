"""PackageSentinel FastAPI application entrypoint."""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator, Dict
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api.routes import reports, scans
from app.config import get_settings
from app.database.connection import close_db, get_engine, init_db

# Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("packagesentinel")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan managing database initialization and cleanup."""
    logger.info("Starting up PackageSentinel backend...")
    # Initialize database tables
    await init_db()
    yield
    logger.info("Shutting down PackageSentinel backend...")
    await close_db()


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="PackageSentinel Security Platform - Backend Intelligence & Orchestration Service",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routers under /api/v1
app.include_router(scans.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get(
    "/api/v1/health",
    tags=["Health"],
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description="Returns backend service health and database connectivity status.",
)
async def health_check() -> Dict[str, str]:
    """Check health and verify database connectivity."""
    db_status = "connected"
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        logger.error("Health check database probe failed: %s", exc)
        db_status = f"unhealthy: {str(exc)}"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "app": settings.app_name,
        "version": settings.app_version,
        "database": db_status,
    }

