"""
Async SQLAlchemy engine/session setup for the inventory store.

SQLite is the single runtime inventory/state store (see architecture plan
§5): a flat JSON file cannot express Customer->Site->Device->VDOM
relationships or answer "all firewalls of customer Alfa". This module owns
engine/session construction only -- schema lives in `models_orm.py`.
"""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

DEFAULT_DB_PATH = Path("config") / "inventory.db"


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model in `models_orm.py`."""


def default_database_url() -> str:
    """`FORTINET_MCP_DB_URL` overrides the default local SQLite file, e.g.
    for pointing tests at an in-memory database."""
    env_url = os.getenv("FORTINET_MCP_DB_URL")
    if env_url:
        return env_url
    return f"sqlite+aiosqlite:///{DEFAULT_DB_PATH.as_posix()}"


def create_engine(database_url: str | None = None) -> AsyncEngine:
    return create_async_engine(database_url or default_database_url(), future=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_models(engine: AsyncEngine) -> None:
    """Create all tables if they don't exist yet.

    No migration framework at this phase -- acceptable for a single-writer
    local SQLite inventory store; revisit once the schema needs to evolve
    across releases without a fresh database.
    """
    from . import models_orm  # noqa: F401  (registers tables on Base.metadata)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
