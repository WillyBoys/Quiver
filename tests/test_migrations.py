"""Migrations must match the models exactly (the same check as `alembic check`)."""

import asyncio

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy.ext.asyncio import create_async_engine

from quiver.core.models import Base


def test_models_match_migrations(migrated_db):
    async def diff():
        engine = create_async_engine(migrated_db)
        async with engine.connect() as conn:
            result = await conn.run_sync(
                lambda sync_conn: compare_metadata(
                    MigrationContext.configure(sync_conn, opts={"compare_type": True}),
                    Base.metadata,
                )
            )
        await engine.dispose()
        return result

    assert asyncio.run(diff()) == [], "models changed without a migration (run autogenerate)"
