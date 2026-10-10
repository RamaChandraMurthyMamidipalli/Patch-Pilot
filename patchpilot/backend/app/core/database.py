"""SQLAlchemy 2.0 async database engine and session factory."""

from __future__ import annotations

from typing import AsyncIterator

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

logger = structlog.get_logger(__name__)


class Base(DeclarativeBase):
    """Base class for all ORM models."""
    pass


def _make_engine(url: str) -> AsyncEngine:
    if "sqlite" in url:
        return create_async_engine(
            url,
            echo=settings.APP_ENV == "development" and settings.LOG_LEVEL == "DEBUG",
        )
    try:
        return create_async_engine(
            url,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_timeout=settings.DB_POOL_TIMEOUT,
            pool_pre_ping=True,
            echo=settings.APP_ENV == "development" and settings.LOG_LEVEL == "DEBUG",
        )
    except Exception as e:
        logger.warning("failed_creating_postgres_engine_falling_back_to_sqlite", error=str(e))
        return create_async_engine(
            "sqlite+aiosqlite:///./patchpilot.db",
            echo=settings.APP_ENV == "development" and settings.LOG_LEVEL == "DEBUG",
        )

db_url = settings.DATABASE_URL
engine: AsyncEngine = _make_engine(db_url)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Keep attributes accessible after commit
    autoflush=False,
)


async def init_db() -> None:
    """Verify database connectivity on startup, falling back to SQLite if needed."""
    global engine, AsyncSessionLocal
    try:
        async with engine.connect() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        logger.info("database_connection_verified")
    except Exception as e:
        logger.warning("postgres_unavailable_falling_back_to_sqlite", error=str(e))
        db_url = "sqlite+aiosqlite:///./patchpilot.db"
        engine = _make_engine(db_url)
        AsyncSessionLocal.configure(bind=engine)
        import app.models.models  # ensure models are registered
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("sqlite_database_initialized_and_tables_created")


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yield an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
