"""SQLite + async SQLAlchemy setup for BrokenCheckout.

Async engine is required because the intentional race-condition vulnerabilities
in payments/refunds rely on cooperative scheduling between concurrent requests.
"""
from __future__ import annotations

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./brokencheckout.db",
)

engine = create_async_engine(DATABASE_URL, echo=False, future=True)
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


async def init_db() -> None:
    import models  # noqa: F401 — register mappers before create_all

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
