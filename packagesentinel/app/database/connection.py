"""Database connection and session lifecycle management."""

import logging
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.config import get_settings
from app.database.models import Base

logger = logging.getLogger(__name__)

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def set_engine(engine: Optional[AsyncEngine]) -> None:
    """Explicitly set or reset the active engine and sessionmaker (used for testing)."""
    global _engine, _sessionmaker
    _engine = engine
    if engine is not None:
        _sessionmaker = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
    else:
        _sessionmaker = None


def get_engine() -> AsyncEngine:
    """Retrieve or initialize the SQLAlchemy async engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        db_url = settings.database_url
        logger.info("Initializing async database engine with URL: %s", db_url)

        # Configure connection arguments depending on dialect
        connect_args = {}
        if db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        _engine = create_async_engine(
            db_url,
            echo=settings.db_echo,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Retrieve or initialize the async session factory."""
    global _sessionmaker
    if _sessionmaker is None:
        engine = get_engine()
        _sessionmaker = async_sessionmaker(
            bind=engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _sessionmaker


async def init_db() -> None:
    """Create all database tables if they do not exist."""
    engine = get_engine()
    async with engine.begin() as conn:
        logger.info("Creating database tables if not present...")
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schema initialized successfully.")


async def close_db() -> None:
    """Dispose of the database engine pool on application shutdown."""
    global _engine, _sessionmaker
    if _engine is not None:
        logger.info("Disposing database connection pool...")
        await _engine.dispose()
        _engine = None
        _sessionmaker = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session."""
    session_factory = get_sessionmaker()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
