"""Alembic environment: runs migrations over the async engine built from Quiver settings."""

import asyncio

from alembic import context
from sqlalchemy.engine import Connection

from quiver.core.config import get_settings
from quiver.core.db import make_engine
from quiver.core.models import Base

target_metadata = Base.metadata


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


async def _run_online() -> None:
    engine = make_engine(context.config.attributes.get("settings") or get_settings())
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("Offline (SQL script) migrations are not supported; run against a database.")

asyncio.run(_run_online())
