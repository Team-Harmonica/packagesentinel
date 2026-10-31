"""Pytest fixtures and test environment setup."""

import asyncio
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.database.connection import get_db_session, set_engine
from app.database.models import Base
from app.main import app


# In-memory SQLite async database engine with StaticPool for isolated, shared in-memory state
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Provide isolated application settings for testing."""
    return Settings(
        database_url=TEST_DATABASE_URL,
        environment="testing",
        debug=True,
    )


@pytest_asyncio.fixture(scope="function")
async def test_engine():
    """Create a fresh in-memory SQLite engine for each test function."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Wire connection module to this test engine
    set_engine(engine)

    yield engine

    set_engine(None)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Yield an active async database session against the test database."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def async_client(test_engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an asynchronous HTTP test client wired to the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
